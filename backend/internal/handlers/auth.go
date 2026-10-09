package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

const (
	passwordResetTTL       = 30 * time.Minute
	resetRequestsPerHour   = 5  // per email address
	resetRequestsPerIPHour = 20 // per client IP
	maxPasswordBytes       = 72 // bcrypt ignores anything longer

	// Failed sign-ins are throttled per account and per account+client IP.
	loginFailureWindow     = 15 * time.Minute
	loginFailuresPerEmail  = 20
	loginFailuresPerIPUser = 5
)

// usernamePattern matches the characters @mentions recognise, so every username is mentionable.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]{3,50}$`)

// AuthHandler handles registration, login, token refresh and passwords.
//
// Access tokens are opaque random strings whose hash is stored in Redis with a TTL
// (SESSION_TTL seconds), so they can be revoked instantly. Refresh tokens are stored
// hashed in user_sessions and are single-use.
type AuthHandler struct {
	deps *Dependencies
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(deps *Dependencies) *AuthHandler {
	return &AuthHandler{deps: deps}
}

// newAccount is a validated account about to be created.
type newAccount struct {
	Username, Email, FullName, Password string
	CompanyID                           uuid.UUID
	CompanyRole                         string
	MustChangePassword                  bool
}

// validateAccount normalizes the fields of a new account and returns a message for the user if
// they are invalid.
func validateAccount(a *newAccount) string {
	a.Username = strings.TrimSpace(a.Username)
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))
	a.FullName = strings.TrimSpace(a.FullName)
	switch {
	case !usernamePattern.MatchString(a.Username):
		return "username must be 3-50 letters, digits, '_', '.' or '-'"
	case a.FullName == "" || len(a.FullName) > 255:
		return "full name is required (at most 255 characters)"
	case !strings.Contains(a.Email, "@") || len(a.Email) > 255:
		return "a valid email address is required"
	case len(a.Password) < 8 || len(a.Password) > maxPasswordBytes:
		return "password must be 8-72 bytes"
	}
	return ""
}

// errAccountTaken is returned when the username or email is already registered.
var errAccountTaken = errors.New("username or email is already registered")

// createUser inserts a validated account (inside the caller's transaction).
func createUser(ctx context.Context, q queryer, a newAccount) (*models.User, error) {
	// Usernames are unique regardless of case, because @mentions are matched case-insensitively.
	var taken bool
	if err := q.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) = lower($1) OR email = $2)`,
		a.Username, a.Email).Scan(&taken); err != nil {
		return nil, err
	}
	if taken {
		return nil, errAccountTaken
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(a.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user, err := scanUser(q.QueryRowContext(ctx, `
		INSERT INTO users AS u (username, email, password_hash, full_name, public_key, password_changed_at,
			company_id, company_role, must_change_password)
		VALUES ($1, $2, $3, $4, '', NOW(), $5, $6, $7)
		RETURNING `+userColumns("u"),
		a.Username, a.Email, string(hash), a.FullName, a.CompanyID, a.CompanyRole, a.MustChangePassword))
	if isUniqueViolation(err) {
		return nil, errAccountTaken
	}
	if err != nil {
		return nil, err
	}
	if err := q.QueryRowContext(ctx,
		`INSERT INTO user_preferences (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING RETURNING user_id`,
		user.ID).Scan(new(uuid.UUID)); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return user, nil
}

// Register creates an account from a company invitation. The account joins the inviting
// company with the invited role; the email must be the one the invitation was sent to.
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	account := newAccount{Username: req.Username, Email: req.Email, FullName: req.FullName, Password: req.Password}
	if msg := validateAccount(&account); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	ctx := c.Request.Context()
	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()

	var inviteID uuid.UUID
	var inviteEmail string
	err = tx.QueryRowContext(ctx, `
		SELECT id, company_id, email, company_role FROM invitations
		WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
		FOR UPDATE`, hashToken(req.InviteToken)).Scan(&inviteID, &account.CompanyID, &inviteEmail, &account.CompanyRole)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this invitation is invalid or has expired; ask your company admin for a new one"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load invitation")
		return
	}
	if !strings.EqualFold(inviteEmail, account.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "use the email address the invitation was sent to: " + inviteEmail})
		return
	}
	company, err := loadCompany(ctx, tx, account.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	if !company.IsActive() {
		c.JSON(http.StatusForbidden, gin.H{"error": companyInactiveMessage(company.Status), "code": "company_inactive"})
		return
	}
	if company.Plan != nil && company.Plan.MaxUsers != nil && company.MemberCount >= *company.Plan.MaxUsers {
		c.JSON(http.StatusForbidden, gin.H{"error": "your company has used all the seats of its plan; ask your company admin"})
		return
	}

	user, err := createUser(ctx, tx, account)
	if errors.Is(err, errAccountTaken) {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "create user")
		return
	}
	if _, err := tx.ExecContext(ctx, `UPDATE invitations SET accepted_at = NOW() WHERE id = $1`, inviteID); err != nil {
		h.deps.internalError(c, err, "accept invitation")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "create user")
		return
	}

	h.deps.Kafka.Publish(ctx, "user.registered", user.ID.String(),
		gin.H{"user_id": user.ID, "username": user.Username, "company_id": user.CompanyID})
	c.JSON(http.StatusCreated, gin.H{"user": user.ToDTO(), "company": company})
}

// companyGate loads the user's company and, unless they are a platform admin, writes a 403 and
// returns false if it is not active.
func (h *AuthHandler) companyGate(c *gin.Context, user *models.User) (*models.Company, bool) {
	company, err := loadCompany(c.Request.Context(), h.deps.DB, user.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return nil, false
	}
	if !company.IsActive() && !user.IsAdmin() {
		c.JSON(http.StatusForbidden, gin.H{
			"error": companyInactiveMessage(company.Status), "code": "company_inactive", "company_status": company.Status,
		})
		return nil, false
	}
	return company, true
}

// Login exchanges email and password for an access token and refresh token. If an admin reset
// the password, the response has user.must_change_password and the session can only be used
// to change it.
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}

	ctx := c.Request.Context()
	email := strings.ToLower(strings.TrimSpace(req.Email))
	emailKey := "login:fail:email:" + email
	ipUserKey := "login:fail:ip:" + c.ClientIP() + ":" + email
	if retry := h.loginBlocked(ctx, emailKey, ipUserKey); retry > 0 {
		c.Header("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed sign-in attempts; try again later"})
		return
	}

	// The user row (password hash, status and session generation) is read in one statement, so
	// a password change or suspension committed after this point invalidates the new session.
	user, err := scanUser(h.deps.DB.QueryRowContext(ctx,
		"SELECT "+userColumns("u")+" FROM users u WHERE u.email = $1 AND u.deleted_at IS NULL", email))
	if errors.Is(err, sql.ErrNoRows) {
		// Compare against a dummy hash so unknown emails take as long as wrong passwords.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		h.recordLoginFailure(ctx, emailKey, ipUserKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load user for login")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		h.recordLoginFailure(ctx, emailKey, ipUserKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	h.deps.Redis.Del(ctx, ipUserKey)
	if !user.IsActive() {
		c.JSON(http.StatusForbidden, gin.H{"error": "this account is " + user.Status + "; contact an administrator"})
		return
	}
	company, ok := h.companyGate(c, user)
	if !ok {
		return
	}

	resp, err := h.issueTokens(c, user)
	if err != nil {
		h.deps.internalError(c, err, "issue tokens")
		return
	}
	resp.Company = company
	if _, err := h.deps.DB.ExecContext(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, user.ID); err != nil {
		h.deps.Logger.WithError(err).Warn("Failed to record last login")
	}

	h.deps.Kafka.Publish(ctx, "user.logged_in", user.ID.String(), gin.H{"user_id": user.ID})
	c.JSON(http.StatusOK, resp)
}

// Refresh exchanges a refresh token for a new token pair. Each refresh token works once.
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}

	ctx := c.Request.Context()
	var userID uuid.UUID
	var generation int64
	err := h.deps.DB.QueryRowContext(ctx, `
		DELETE FROM user_sessions
		WHERE refresh_token_hash = $1 AND expires_at > NOW()
		RETURNING user_id, session_generation`, hashToken(req.RefreshToken),
	).Scan(&userID, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "consume refresh token")
		return
	}

	user, err := loadUser(ctx, h.deps.DB, userID)
	if err != nil || !user.IsActive() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account is not active"})
		return
	}
	if user.SessionGeneration != generation {
		// Issued before a password change, reset or suspension.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}
	company, ok := h.companyGate(c, user)
	if !ok {
		return
	}

	resp, err := h.issueTokens(c, user)
	if err != nil {
		h.deps.internalError(c, err, "issue tokens")
		return
	}
	resp.Company = company
	c.JSON(http.StatusOK, resp)
}

// Me returns the signed-in user's own profile (including role and must_change_password) and
// their company.
func (h *AuthHandler) Me(c *gin.Context) {
	ctx := c.Request.Context()
	user, err := loadUser(ctx, h.deps.DB, middleware.GetUserID(c))
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}
	company, err := loadCompany(ctx, h.deps.DB, user.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "load company")
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user.ToDTO(), "company": company})
}

// Logout revokes the current access token and, if given, the refresh token.
func (h *AuthHandler) Logout(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = c.ShouldBindJSON(&req)

	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	key := middleware.AccessTokenKey(middleware.BearerToken(c))
	if err := h.deps.Redis.Del(ctx, key).Err(); err != nil {
		h.deps.Logger.WithError(err).Error("Failed to revoke access token on logout")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not sign out; try again"})
		return
	}
	h.deps.Redis.SRem(ctx, middleware.UserTokensKey(userID), key)
	h.deps.Hub().DisconnectSession(userID, key)
	if req.RefreshToken != "" {
		if _, err := h.deps.DB.ExecContext(ctx, `DELETE FROM user_sessions WHERE refresh_token_hash = $1 AND user_id = $2`,
			hashToken(req.RefreshToken), userID); err != nil {
			h.deps.Logger.WithError(err).Error("Failed to revoke refresh token on logout")
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not sign out; try again"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"logged_out": true})
}

// ChangePassword sets a new password after checking the current one. It signs out every other
// session and returns a fresh token pair for this one. This is also how users complete a
// password reset done by an admin.
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}

	ctx := c.Request.Context()
	user, err := loadUser(ctx, h.deps.DB, middleware.GetUserID(c))
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	if req.OldPassword == req.NewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the new password must be different from the current one"})
		return
	}
	if !passwordLengthOK(c, req.NewPassword) {
		return
	}

	generation, err := setUserPassword(ctx, h.deps, user.ID, req.NewPassword, false)
	if err != nil {
		h.deps.internalError(c, err, "change password")
		return
	}
	user.MustChangePassword = false
	user.SessionGeneration = generation
	resp, err := h.issueTokens(c, user)
	if err != nil {
		h.deps.internalError(c, err, "issue tokens")
		return
	}
	recordAudit(ctx, h.deps, c, user.ID, "update", "user_password", user.ID, gin.H{"event": "password_changed"})
	c.JSON(http.StatusOK, resp)
}

// ForgotPassword emails a single-use reset link valid for 30 minutes. It always responds the
// same way so it cannot be used to find out which emails have accounts.
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	accepted := gin.H{"message": "If an account exists for that email, a reset link has been sent."}

	ctx := c.Request.Context()
	if h.overLimit(ctx, "pwreset:email:"+email, resetRequestsPerHour) ||
		h.overLimit(ctx, "pwreset:ip:"+c.ClientIP(), resetRequestsPerIPHour) {
		c.JSON(http.StatusAccepted, accepted)
		return
	}

	user, err := scanUser(h.deps.DB.QueryRowContext(ctx,
		"SELECT "+userColumns("u")+" FROM users u WHERE u.email = $1 AND u.deleted_at IS NULL", email))
	if err != nil || !user.IsActive() {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			h.deps.Logger.WithError(err).Error("forgot password lookup failed")
		}
		c.JSON(http.StatusAccepted, accepted)
		return
	}

	token, err := randomToken()
	if err != nil {
		h.deps.internalError(c, err, "generate reset token")
		return
	}
	if _, err := h.deps.DB.ExecContext(ctx, `
		INSERT INTO password_resets (user_id, token_hash, expires_at, requested_ip)
		VALUES ($1, $2, NOW() + make_interval(secs => $3), NULLIF($4, '')::inet)`,
		user.ID, hashToken(token), passwordResetTTL.Seconds(), c.ClientIP()); err != nil {
		h.deps.internalError(c, err, "store reset token")
		return
	}

	link := h.deps.Config.Billing.AppBaseURL + "/#reset=" + token
	body := fmt.Sprintf("Hi %s,\n\n"+
		"Someone (hopefully you) asked to reset the password for your BinTalk account.\n\n"+
		"Open this link within 30 minutes to choose a new password:\n\n%s\n\n"+
		"If you did not ask for this, ignore this email; your password will not change.\n\n"+
		"— BinTalk\n", firstNonEmpty(user.FullName, user.Username), link)
	go func() {
		if err := h.deps.Mailer.Send(user.Email, "Reset your BinTalk password", body); err != nil {
			h.deps.Logger.WithError(err).WithField("user_id", user.ID).Error("Failed to send password reset email")
		}
	}()

	recordAudit(ctx, h.deps, c, user.ID, "update", "user_password", user.ID, gin.H{"event": "password_reset_requested"})
	c.JSON(http.StatusAccepted, accepted)
}

// ResetPassword sets a new password using a token from the reset email.
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if !passwordLengthOK(c, req.NewPassword) {
		return
	}

	ctx := c.Request.Context()
	var userID uuid.UUID
	err := h.deps.DB.QueryRowContext(ctx, `
		UPDATE password_resets SET used_at = NOW()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING user_id`, hashToken(req.Token)).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this reset link is invalid or has expired; request a new one"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "use reset token")
		return
	}

	user, err := loadUser(ctx, h.deps.DB, userID)
	if err != nil || !user.IsActive() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this account cannot be reset; contact an administrator"})
		return
	}
	if _, err := setUserPassword(ctx, h.deps, userID, req.NewPassword, false); err != nil {
		h.deps.internalError(c, err, "reset password")
		return
	}
	// Any other outstanding reset links stop working.
	_, _ = h.deps.DB.ExecContext(ctx,
		`UPDATE password_resets SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, userID)

	recordAudit(ctx, h.deps, c, userID, "update", "user_password", userID, gin.H{"event": "password_reset_completed"})
	c.JSON(http.StatusOK, gin.H{"message": "Your password has been changed. You can now sign in."})
}

// passwordLengthOK writes a 400 response and returns false if the password is longer than
// bcrypt accepts. The limit is in bytes, so multibyte passwords hit it with fewer characters.
func passwordLengthOK(c *gin.Context, password string) bool {
	if len(password) > maxPasswordBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at most 72 bytes"})
		return false
	}
	return true
}

// setUserPassword stores a new password hash, sets the must-change flag, and signs the user out
// of every session. It returns the user's new session generation.
func setUserPassword(ctx context.Context, deps *Dependencies, userID uuid.UUID, password string, mustChange bool) (int64, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	var generation int64
	if err := deps.DB.QueryRowContext(ctx, `
		UPDATE users SET password_hash = $2, must_change_password = $3, password_changed_at = NOW(),
			session_generation = session_generation + 1
		WHERE id = $1
		RETURNING session_generation`, userID, string(hash), mustChange).Scan(&generation); err != nil {
		return 0, err
	}
	return generation, revokeSessions(ctx, deps, userID, generation)
}

// revokeSessions signs a user out everywhere after their session generation was incremented in
// the database (to generation). Publishing the generation is what invalidates sessions, including
// ones issued concurrently; deleting the tokens and closing sockets is cleanup on top of that.
func revokeSessions(ctx context.Context, deps *Dependencies, userID uuid.UUID, generation int64) error {
	if err := middleware.StoreSessionGeneration(ctx, deps.Redis, userID, generation); err != nil {
		return err
	}
	deps.Hub().DisconnectUser(userID)
	deps.Calls().DropUser(userID)

	setKey := middleware.UserTokensKey(userID)
	keys, err := deps.Redis.SMembers(ctx, setKey).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		if err := deps.Redis.Del(ctx, keys...).Err(); err != nil {
			return err
		}
	}
	if err := deps.Redis.Del(ctx, setKey).Err(); err != nil {
		return err
	}
	_, err = deps.DB.ExecContext(ctx, `DELETE FROM user_sessions WHERE user_id = $1`, userID)
	return err
}

func (h *AuthHandler) issueTokens(c *gin.Context, user *models.User) (*models.LoginResponse, error) {
	accessToken, err := randomToken()
	if err != nil {
		return nil, err
	}
	refreshToken, err := randomToken()
	if err != nil {
		return nil, err
	}

	ctx := c.Request.Context()
	accessTTL := h.deps.Config.Session.AccessTTL
	refreshTTL := h.deps.Config.Session.RefreshTTL
	key := middleware.AccessTokenKey(accessToken)
	setKey := middleware.UserTokensKey(user.ID)
	h.pruneTokenSet(ctx, setKey)
	pipe := h.deps.Redis.TxPipeline()
	pipe.Set(ctx, key, middleware.SessionValue(user.ID, user.SessionGeneration, user.MustChangePassword), accessTTL)
	pipe.SAdd(ctx, setKey, key)
	pipe.Expire(ctx, setKey, refreshTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}

	_, err = h.deps.DB.ExecContext(ctx, `
		INSERT INTO user_sessions (user_id, refresh_token_hash, expires_at, ip_address, user_agent, session_generation)
		VALUES ($1, $2, NOW() + make_interval(secs => $3), NULLIF($4, '')::inet, $5, $6)`,
		user.ID, hashToken(refreshToken), refreshTTL.Seconds(), c.ClientIP(), c.Request.UserAgent(),
		user.SessionGeneration,
	)
	if err != nil {
		return nil, err
	}

	return &models.LoginResponse{
		Token: accessToken, RefreshToken: refreshToken,
		ExpiresIn: int64(accessTTL.Seconds()), User: user.ToDTO(),
	}, nil
}

// overLimit counts an event in a one-hour window and reports whether it exceeded limit.
func (h *AuthHandler) overLimit(ctx context.Context, key string, limit int64) bool {
	pipe := h.deps.Redis.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.ExpireNX(ctx, key, time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return false
	}
	return incr.Val() > limit
}

// loginBlocked reports how long sign-in is blocked for these failure counters (0 if it is not).
// If Redis is unavailable sign-in is allowed: the counters only slow down password guessing.
func (h *AuthHandler) loginBlocked(ctx context.Context, emailKey, ipUserKey string) time.Duration {
	pipe := h.deps.Redis.Pipeline()
	byEmail := pipe.Get(ctx, emailKey)
	byIPUser := pipe.Get(ctx, ipUserKey)
	_, _ = pipe.Exec(ctx)
	for _, check := range []struct {
		cmd   *redis.StringCmd
		key   string
		limit int64
	}{{byEmail, emailKey, loginFailuresPerEmail}, {byIPUser, ipUserKey, loginFailuresPerIPUser}} {
		if n, err := check.cmd.Int64(); err == nil && n >= check.limit {
			if ttl, err := h.deps.Redis.TTL(ctx, check.key).Result(); err == nil && ttl > 0 {
				return ttl
			}
			return loginFailureWindow
		}
	}
	return 0
}

func (h *AuthHandler) recordLoginFailure(ctx context.Context, keys ...string) {
	pipe := h.deps.Redis.TxPipeline()
	for _, key := range keys {
		pipe.Incr(ctx, key)
		pipe.ExpireNX(ctx, key, loginFailureWindow)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		h.deps.Logger.WithError(err).Warn("Failed to record failed sign-in")
	}
}

// pruneTokenSet removes keys of expired access tokens from a user's token set, so the set does
// not grow forever for users who keep signing in.
func (h *AuthHandler) pruneTokenSet(ctx context.Context, setKey string) {
	keys, err := h.deps.Redis.SMembers(ctx, setKey).Result()
	if err != nil || len(keys) < 16 {
		return
	}
	pipe := h.deps.Redis.Pipeline()
	exists := make([]*redis.IntCmd, len(keys))
	for i, key := range keys {
		exists[i] = pipe.Exists(ctx, key)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return
	}
	var dead []interface{}
	for i, cmd := range exists {
		if cmd.Val() == 0 {
			dead = append(dead, keys[i])
		}
	}
	if len(dead) > 0 {
		h.deps.Redis.SRem(ctx, setKey, dead...)
	}
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), bcrypt.DefaultCost)

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
