package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

// AdminHandler serves the admin console: statistics, user management, abuse reports and the
// audit log. All routes require the admin role (middleware.RequireAdmin).
type AdminHandler struct {
	deps *Dependencies
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(deps *Dependencies) *AdminHandler {
	return &AdminHandler{deps: deps}
}

// ---------- audit log ----------

// recordAudit writes an entry to audit_logs. c may be nil for actions without a request.
func recordAudit(ctx context.Context, deps *Dependencies, c *gin.Context, actor uuid.UUID, action, resourceType string, resourceID uuid.UUID, details gin.H) {
	payload, _ := json.Marshal(details)
	var ip, agent string
	if c != nil {
		ip, agent = c.ClientIP(), c.Request.UserAgent()
	}
	var actorParam interface{}
	if actor != uuid.Nil {
		actorParam = actor
	}
	if _, err := deps.DB.ExecContext(ctx, `
		INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::inet, NULLIF($7, ''))`,
		actorParam, action, resourceType, resourceID, string(payload), ip, agent); err != nil {
		deps.Logger.WithError(err).Warn("Failed to write audit log")
	}
}

// ---------- bootstrap ----------

// EnsureBootstrapAdmin makes sure at least one admin exists. If none does, an admin account is
// created for BOOTSTRAP_ADMIN_EMAIL with BOOTSTRAP_ADMIN_PASSWORD, which must be changed at first
// sign-in. Existing accounts are never promoted implicitly (anyone could have registered that
// address); an operator promotes them with `api-server make-admin <email>`.
func EnsureBootstrapAdmin(ctx context.Context, deps *Dependencies) {
	if deps.Mailer != nil && deps.Mailer.Status().Development {
		deps.Logger.Warn("Email goes to the local Mailpit server (http://localhost:8025), not to real inboxes. " +
			"Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD and SMTP_FROM in .env to deliver real email.")
	}

	var admins int
	if err := deps.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin' AND deleted_at IS NULL`).Scan(&admins); err != nil {
		deps.Logger.WithError(err).Error("Failed to check for admin accounts")
		return
	}
	if admins > 0 {
		return
	}

	email := strings.ToLower(strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_EMAIL")))
	if email == "" {
		deps.Logger.Warn("No admin account exists. Set BOOTSTRAP_ADMIN_EMAIL or run `api-server make-admin <email>`.")
		return
	}

	var exists bool
	if err := deps.DB.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists); err != nil {
		deps.Logger.WithError(err).Error("Failed to look up bootstrap admin")
		return
	}
	if exists {
		deps.Logger.Warnf("No admin account exists, and an account for BOOTSTRAP_ADMIN_EMAIL (%s) was already "+
			"registered. It is not promoted automatically; if it is yours, run `api-server make-admin %s`.", email, email)
		return
	}

	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if len(password) < 8 || len(password) > maxPasswordBytes {
		deps.Logger.Warn("No admin account exists. Set BOOTSTRAP_ADMIN_PASSWORD (8-72 bytes) to create one " +
			"for BOOTSTRAP_ADMIN_EMAIL, or run `api-server make-admin <email>`.")
		return
	}
	var id uuid.UUID
	err := deps.DB.QueryRowContext(ctx, `
		INSERT INTO users (username, email, password_hash, full_name, public_key, role, must_change_password,
			company_id, company_role)
		VALUES ($1, $2, '!', 'Administrator', '', 'admin', true,
			(SELECT id FROM companies WHERE slug = 'default'), 'owner')
		RETURNING id`, firstNonEmpty(os.Getenv("BOOTSTRAP_ADMIN_USERNAME"), "admin"), email).Scan(&id)
	if err != nil {
		deps.Logger.WithError(err).Error("Failed to create bootstrap admin")
		return
	}
	if _, err := setUserPassword(ctx, deps, id, password, true); err != nil {
		deps.Logger.WithError(err).Error("Failed to set bootstrap admin password")
		return
	}
	deps.Logger.Warnf("Created admin account %s with the BOOTSTRAP_ADMIN_PASSWORD (must be changed at first sign-in)", email)
}

// PromoteToAdmin gives an existing account the admin role (used by `api-server make-admin`).
func PromoteToAdmin(ctx context.Context, deps *Dependencies, email string) error {
	res, err := deps.DB.ExecContext(ctx,
		`UPDATE users SET role = 'admin' WHERE email = $1 AND deleted_at IS NULL`, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no account with that email")
	}
	return nil
}

// generatePassword returns a random 14-character password without ambiguous characters.
func generatePassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 14)
	for i := range out {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		out[i] = alphabet[n.Int64()]
	}
	return string(out[:7]) + "-" + string(out[7:])
}

// scope returns the company an admin request is limited to: the caller's own company for company
// owners and admins; for platform admins all companies (nil), or the one in ?company_id=.
func (h *AdminHandler) scope(c *gin.Context) (*uuid.UUID, actor, bool) {
	a, ok := currentActor(c, h.deps)
	if !ok {
		return nil, a, false
	}
	if !a.IsPlatformAdmin() {
		return &a.CompanyID, a, true
	}
	if raw := c.Query("company_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid company_id"})
			return nil, a, false
		}
		return &id, a, true
	}
	return nil, a, true
}

// canManage reports whether actor a may change target's account: platform admins anyone but
// themselves; company admins the members and admins of their company, but not its owner or
// platform admins.
func canManage(a actor, target *models.User) bool {
	if target.ID == a.ID {
		return false
	}
	if a.IsPlatformAdmin() {
		return true
	}
	return a.IsCompanyAdmin() && target.CompanyID == a.CompanyID &&
		target.CompanyRole != models.CompanyOwner && !target.IsAdmin()
}

// ---------- statistics ----------

// Stats returns counts for the admin overview, for the caller's scope (see scope).
func (h *AdminHandler) Stats(c *gin.Context) {
	company, a, ok := h.scope(c)
	if !ok {
		return
	}
	var s struct {
		Platform         bool `json:"platform"`
		Companies        int  `json:"companies"`
		PendingCompanies int  `json:"pending_companies"`
		Users          int `json:"users"`
		ActiveUsers    int `json:"active_users"`
		SuspendedUsers int `json:"suspended_users"`
		Admins         int `json:"admins"`
		ActiveToday    int `json:"active_today"`
		Groups         int `json:"groups"`
		Messages       int `json:"messages"`
		Messages24h    int `json:"messages_24h"`
		Files          int `json:"files"`
		OpenReports    int `json:"open_reports"`
		Email          interface{} `json:"email"`
	}
	// $1: company filter (NULL = all). Admins are platform admins for the whole service, and
	// company owners/admins within a company.
	err := h.deps.DB.QueryRowContext(c.Request.Context(), `
		WITH scoped AS (SELECT * FROM users WHERE deleted_at IS NULL AND ($1::uuid IS NULL OR company_id = $1))
		SELECT
			(SELECT COUNT(*) FROM scoped),
			(SELECT COUNT(*) FROM scoped WHERE status = 'active'),
			(SELECT COUNT(*) FROM scoped WHERE status = 'suspended'),
			(SELECT COUNT(*) FROM scoped WHERE CASE WHEN $1::uuid IS NULL THEN role = 'admin'
				ELSE company_role IN ('owner', 'admin') END),
			(SELECT COUNT(*) FROM scoped WHERE last_login_at > NOW() - INTERVAL '24 hours'),
			(SELECT COUNT(*) FROM groups WHERE deleted_at IS NULL AND ($1::uuid IS NULL OR company_id = $1)),
			(SELECT COUNT(*) FROM messages WHERE NOT COALESCE(is_deleted, false)
				AND ($1::uuid IS NULL OR sender_id IN (SELECT id FROM scoped))),
			(SELECT COUNT(*) FROM messages WHERE created_at > NOW() - INTERVAL '24 hours'
				AND ($1::uuid IS NULL OR sender_id IN (SELECT id FROM scoped))),
			(SELECT COUNT(*) FROM files WHERE deleted_at IS NULL
				AND ($1::uuid IS NULL OR uploaded_by IN (SELECT id FROM scoped))),
			(SELECT COUNT(*) FROM abuse_reports WHERE status = 'open'
				AND ($1::uuid IS NULL OR reporter_id IN (SELECT id FROM scoped))),
			(SELECT COUNT(*) FROM companies),
			(SELECT COUNT(*) FROM companies WHERE status = 'pending_approval')`, company,
	).Scan(&s.Users, &s.ActiveUsers, &s.SuspendedUsers, &s.Admins, &s.ActiveToday,
		&s.Groups, &s.Messages, &s.Messages24h, &s.Files, &s.OpenReports, &s.Companies, &s.PendingCompanies)
	if err != nil {
		h.deps.internalError(c, err, "load admin stats")
		return
	}
	s.Platform = a.IsPlatformAdmin()
	if s.Platform {
		s.Email = h.deps.Mailer.Status()
	} else {
		s.Companies, s.PendingCompanies = 0, 0
	}
	c.JSON(http.StatusOK, s)
}

// ---------- users ----------

type adminUser struct {
	*models.UserDTO
	CompanyName      string     `json:"company_name"`
	LastLoginAt      *time.Time `json:"last_login_at"`
	MessageCount     int        `json:"message_count"`
	ReportsAgainst   int        `json:"open_reports_against"`
	PasswordChangeAt *time.Time `json:"password_changed_at"`
}

// ListUsers lists accounts with optional search (q) and status/role filters.
func (h *AdminHandler) ListUsers(c *gin.Context) {
	company, _, ok := h.scope(c)
	if !ok {
		return
	}
	limit, offset := paging(c)
	q := "%" + escapeLike(strings.TrimSpace(c.Query("q"))) + "%"
	rows, err := h.deps.DB.QueryContext(c.Request.Context(), `
		SELECT `+userColumns("u")+`, co.name, u.password_changed_at,
			(SELECT COUNT(*) FROM messages m WHERE m.sender_id = u.id),
			(SELECT COUNT(*) FROM abuse_reports r WHERE r.reported_user_id = u.id AND r.status = 'open'),
			COUNT(*) OVER ()
		FROM users u JOIN companies co ON co.id = u.company_id
		WHERE u.deleted_at IS NULL
		  AND (u.username ILIKE $1 OR u.email ILIKE $1 OR u.full_name ILIKE $1)
		  AND ($2 = '' OR u.status::text = $2)
		  AND ($3 = '' OR u.role = $3)
		  AND ($6::uuid IS NULL OR u.company_id = $6)
		ORDER BY (u.role = 'admin') DESC, (u.company_role = 'owner') DESC, u.created_at DESC
		LIMIT $4 OFFSET $5`, q, c.Query("status"), c.Query("role"), limit, offset, company)
	if err != nil {
		h.deps.internalError(c, err, "list users")
		return
	}
	defer rows.Close()

	users := []adminUser{}
	total := 0
	for rows.Next() {
		var a adminUser
		user, err := scanUser(rows, &a.CompanyName, &a.PasswordChangeAt, &a.MessageCount, &a.ReportsAgainst, &total)
		if err != nil {
			h.deps.internalError(c, err, "scan user")
			return
		}
		a.UserDTO, a.LastLoginAt = user.ToDTO(), user.LastLoginAt
		users = append(users, a)
	}
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list users")
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users, "total": total, "limit": limit, "offset": offset})
}

// UpdateUser changes a user's status (active/suspended), company role (admin/member) and, for
// platform admins, platform role (user/admin). Nobody can change their own account here, the
// last platform admin cannot be demoted, and company admins cannot change their company's owner.
func (h *AdminHandler) UpdateUser(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	var req struct {
		Status      string `json:"status"`
		Role        string `json:"role"`
		CompanyRole string `json:"company_role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if req.Status != "" && req.Status != "active" && req.Status != "suspended" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be active or suspended"})
		return
	}
	if req.Role != "" && req.Role != "user" && req.Role != "admin" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be user or admin"})
		return
	}
	if req.CompanyRole != "" && req.CompanyRole != models.CompanyAdmin && req.CompanyRole != models.CompanyMember {
		c.JSON(http.StatusBadRequest, gin.H{"error": "company_role must be admin or member"})
		return
	}
	if req.Role != "" && !a.IsPlatformAdmin() {
		c.JSON(http.StatusForbidden, gin.H{"error": "only platform admins can change platform roles"})
		return
	}
	adminID := middleware.GetUserID(c)
	if id == adminID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot change your own status or role"})
		return
	}

	ctx := c.Request.Context()
	before, err := loadUser(ctx, h.deps.DB, id)
	if errors.Is(err, errNotFound) || (err == nil && before.IsDeleted()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}
	if !a.IsPlatformAdmin() && before.CompanyID != a.CompanyID {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if !canManage(a, before) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you cannot change this account"})
		return
	}
	if req.CompanyRole != "" && before.CompanyRole == models.CompanyOwner {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the company owner's role cannot be changed"})
		return
	}
	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()
	if req.Role == "user" && before.IsAdmin() {
		// Lock every admin row so two admins demoting each other cannot leave none.
		var admins int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
			SELECT id FROM users WHERE role = 'admin' AND deleted_at IS NULL FOR UPDATE) a`).Scan(&admins); err != nil {
			h.deps.internalError(c, err, "count admins")
			return
		}
		if admins <= 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot remove the last admin"})
			return
		}
	}

	// Suspending an account increments its session generation, which ends all its sessions.
	user, err := scanUser(tx.QueryRowContext(ctx, `
		UPDATE users AS u SET
			status = COALESCE(NULLIF($2, '')::user_status, u.status),
			role   = COALESCE(NULLIF($3, ''), u.role),
			company_role = COALESCE(NULLIF($4, ''), u.company_role),
			session_generation = u.session_generation +
				CASE WHEN $2 = 'suspended' AND u.status <> 'suspended' THEN 1 ELSE 0 END
		WHERE u.id = $1
		RETURNING `+userColumns("u"), id, req.Status, req.Role, req.CompanyRole))
	if err != nil {
		h.deps.internalError(c, err, "update user")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "update user")
		return
	}

	if req.Status == "suspended" && before.Status != "suspended" {
		h.deps.Hub().SendToUsers([]uuid.UUID{id}, "account.suspended", gin.H{})
		if err := revokeSessions(ctx, h.deps, id, user.SessionGeneration); err != nil {
			h.deps.Logger.WithError(err).Error("Failed to revoke sessions of suspended user")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "the account was suspended, but its open sessions could not all be ended yet; " +
					"they stop working within a minute",
				"user": user.ToDTO(),
			})
			return
		}
	}
	if (req.Role != "" && req.Role != before.Role) || (req.CompanyRole != "" && req.CompanyRole != before.CompanyRole) {
		h.deps.Hub().SendToUsers([]uuid.UUID{id}, "account.updated", gin.H{"role": user.Role, "company_role": user.CompanyRole})
	}

	recordAudit(ctx, h.deps, c, adminID, "update", "user", id, gin.H{
		"username": user.Username,
		"status":       gin.H{"from": before.Status, "to": user.Status},
		"role":         gin.H{"from": before.Role, "to": user.Role},
		"company_role": gin.H{"from": before.CompanyRole, "to": user.CompanyRole},
	})
	c.JSON(http.StatusOK, gin.H{"user": user.ToDTO()})
}

// ResetUserPassword sets a temporary password (the given one, or a generated one) that the user
// must change at their next sign-in, and signs them out everywhere. The temporary password is
// returned once so the admin can pass it on.
func (h *AdminHandler) ResetUserPassword(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password" binding:"omitempty,min=8,max=72"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}

	ctx := c.Request.Context()
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	user, err := loadUser(ctx, h.deps.DB, id)
	if errors.Is(err, errNotFound) || (err == nil && (user.IsDeleted() || (!a.IsPlatformAdmin() && user.CompanyID != a.CompanyID))) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}
	if !canManage(a, user) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you cannot reset this account's password"})
		return
	}

	password := req.Password
	if password == "" {
		password = generatePassword()
	}
	if !passwordLengthOK(c, password) {
		return
	}
	// Tell the user's open apps before their sockets are closed.
	h.deps.Hub().SendToUsers([]uuid.UUID{id}, "account.password_reset", gin.H{})
	if _, err := setUserPassword(ctx, h.deps, id, password, true); err != nil {
		h.deps.internalError(c, err, "reset password")
		return
	}

	recordAudit(ctx, h.deps, c, middleware.GetUserID(c), "update", "user_password", id,
		gin.H{"event": "admin_password_reset", "username": user.Username})
	c.JSON(http.StatusOK, gin.H{
		"temporary_password":   password,
		"must_change_password": true,
		"user":                 user.ToDTO(),
	})
}

// ---------- abuse reports ----------

type reportedMessage struct {
	ID          uuid.UUID        `json:"id"`
	Content     string           `json:"content"`
	MessageType string           `json:"message_type"`
	Attachments []models.FileDTO `json:"attachments,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	IsDeleted   bool             `json:"is_deleted"`
	GroupName   string           `json:"group_name,omitempty"`
	InThread    bool             `json:"in_thread"`
}

type reportDTO struct {
	ID             uuid.UUID        `json:"id"`
	Reason         string           `json:"reason"`
	Details        string           `json:"details"`
	Status         string           `json:"status"`
	ActionTaken    string           `json:"action_taken,omitempty"`
	ResolutionNote string           `json:"resolution_note,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	ResolvedAt     *time.Time       `json:"resolved_at,omitempty"`
	Reporter       *models.UserDTO  `json:"reporter"`
	ReportedUser   *models.UserDTO  `json:"reported_user,omitempty"`
	ResolvedBy     *models.UserDTO  `json:"resolved_by,omitempty"`
	Message        *reportedMessage `json:"message,omitempty"`
	ReportCount    int              `json:"report_count"` // open reports about the same message/user
}

// ListReports lists abuse reports (status=open|resolved|dismissed|all, default open), newest first.
// Reported message content is decrypted for the admin.
func (h *AdminHandler) ListReports(c *gin.Context) {
	company, _, ok := h.scope(c)
	if !ok {
		return
	}
	limit, offset := paging(c)
	status := c.DefaultQuery("status", "open")
	if status == "all" {
		status = ""
	}

	ctx := c.Request.Context()
	rows, err := h.deps.DB.QueryContext(ctx, `
		SELECT r.id, r.reason, COALESCE(r.details, ''), r.status, COALESCE(r.action_taken, ''),
			COALESCE(r.resolution_note, ''), r.created_at, r.resolved_at,
			r.reporter_id, r.reported_user_id, r.resolved_by, r.message_id,
			(SELECT COUNT(*) FROM abuse_reports x WHERE x.status = 'open'
			   AND ((r.message_id IS NOT NULL AND x.message_id = r.message_id)
			     OR (r.message_id IS NULL AND x.reported_user_id = r.reported_user_id))),
			COUNT(*) OVER ()
		FROM abuse_reports r
		WHERE ($1 = '' OR r.status = $1)
		  AND ($4::uuid IS NULL OR r.reporter_id IN (SELECT id FROM users WHERE company_id = $4))
		ORDER BY r.created_at DESC
		LIMIT $2 OFFSET $3`, status, limit, offset, company)
	if err != nil {
		h.deps.internalError(c, err, "list reports")
		return
	}

	type rowRefs struct{ reporter, reported, resolver, message *uuid.UUID }
	var reports []reportDTO
	var refs []rowRefs
	total := 0
	userIDs := map[uuid.UUID]bool{}
	var messageIDs []string
	for rows.Next() {
		var r reportDTO
		var ref rowRefs
		var reporter uuid.UUID
		if err := rows.Scan(&r.ID, &r.Reason, &r.Details, &r.Status, &r.ActionTaken, &r.ResolutionNote,
			&r.CreatedAt, &r.ResolvedAt, &reporter, &ref.reported, &ref.resolver, &ref.message,
			&r.ReportCount, &total); err != nil {
			rows.Close()
			h.deps.internalError(c, err, "scan report")
			return
		}
		ref.reporter = &reporter
		for _, id := range []*uuid.UUID{ref.reporter, ref.reported, ref.resolver} {
			if id != nil {
				userIDs[*id] = true
			}
		}
		if ref.message != nil {
			messageIDs = append(messageIDs, ref.message.String())
		}
		reports = append(reports, r)
		refs = append(refs, ref)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list reports")
		return
	}

	users, err := loadUserDTOs(ctx, h.deps.DB, userIDs)
	if err != nil {
		h.deps.internalError(c, err, "load report users")
		return
	}
	messages, err := h.loadReportedMessages(ctx, messageIDs)
	if err != nil {
		h.deps.internalError(c, err, "load reported messages")
		return
	}
	for i := range reports {
		ref := refs[i]
		reports[i].Reporter = users[*ref.reporter]
		if ref.reported != nil {
			reports[i].ReportedUser = users[*ref.reported]
		}
		if ref.resolver != nil {
			reports[i].ResolvedBy = users[*ref.resolver]
		}
		if ref.message != nil {
			reports[i].Message = messages[*ref.message]
		}
	}
	if reports == nil {
		reports = []reportDTO{}
	}
	c.JSON(http.StatusOK, gin.H{"reports": reports, "total": total, "limit": limit, "offset": offset})
}

func (h *AdminHandler) loadReportedMessages(ctx context.Context, ids []string) (map[uuid.UUID]*reportedMessage, error) {
	out := map[uuid.UUID]*reportedMessage{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := h.deps.DB.QueryContext(ctx, `
		SELECT `+messageColumns+`, COALESCE(g.name, '')
		FROM messages m LEFT JOIN groups g ON g.id = m.group_id
		WHERE m.id = ANY($1)`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	var dtos []models.MessageDTO
	var extras []*reportedMessage
	for rows.Next() {
		var groupName string
		msg, err := scanMessage(rows, &groupName)
		if err != nil {
			rows.Close()
			return nil, err
		}
		rm := &reportedMessage{
			ID: msg.ID, Content: decryptMessage(h.deps, msg), MessageType: msg.MessageType,
			CreatedAt: msg.CreatedAt, IsDeleted: msg.IsDeleted, GroupName: groupName, InThread: msg.ParentID != nil,
		}
		out[msg.ID] = rm
		dtos = append(dtos, models.MessageDTO{ID: msg.ID, FileID: msg.FileID})
		extras = append(extras, rm)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := enrichMessages(ctx, h.deps.DB, dtos); err != nil {
		return nil, err
	}
	for i := range dtos {
		extras[i].Attachments = dtos[i].Attachments
	}
	return out, nil
}

// UpdateReport resolves or dismisses a report, optionally deleting the reported message and/or
// suspending the reported user. Other open reports about the same message are closed too.
func (h *AdminHandler) UpdateReport(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req struct {
		Status        string `json:"status" binding:"required,oneof=resolved dismissed open"`
		Note          string `json:"note" binding:"max=2000"`
		DeleteMessage bool   `json:"delete_message"`
		SuspendUser   bool   `json:"suspend_user"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}

	ctx := c.Request.Context()
	a, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	adminID := a.ID
	var messageID, reportedUser *uuid.UUID
	var reporterCompany uuid.UUID
	err := h.deps.DB.QueryRowContext(ctx, `
		SELECT r.message_id, r.reported_user_id, u.company_id
		FROM abuse_reports r JOIN users u ON u.id = r.reporter_id WHERE r.id = $1`, id,
	).Scan(&messageID, &reportedUser, &reporterCompany)
	if err == nil && !a.IsPlatformAdmin() && reporterCompany != a.CompanyID {
		err = sql.ErrNoRows
	}
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load report")
		return
	}

	if req.SuspendUser && reportedUser != nil {
		target, err := loadUser(ctx, h.deps.DB, *reportedUser)
		if err != nil {
			h.deps.internalError(c, err, "load reported user")
			return
		}
		if !canManage(a, target) {
			c.JSON(http.StatusForbidden, gin.H{"error": "you cannot suspend this account"})
			return
		}
	}

	// The message deletion, suspension and report update succeed or fail together; notifications
	// and session revocation happen after the commit.
	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()

	var actions []string
	var deleted *deletedMessage
	if req.DeleteMessage && messageID != nil {
		if deleted, err = softDeleteMessage(ctx, tx, *messageID); err != nil {
			h.deps.internalError(c, err, "delete reported message")
			return
		}
		actions = append(actions, "message_deleted")
	}
	var suspendedGeneration int64
	suspended := false
	if req.SuspendUser && reportedUser != nil {
		err := tx.QueryRowContext(ctx, `
			UPDATE users SET status = 'suspended', session_generation = session_generation + 1
			WHERE id = $1 RETURNING session_generation`, *reportedUser).Scan(&suspendedGeneration)
		if err != nil {
			h.deps.internalError(c, err, "suspend user")
			return
		}
		suspended = true
		actions = append(actions, "user_suspended")
	}

	action := strings.Join(actions, ",")
	resolvedBy, resolvedAt := interface{}(adminID), interface{}(time.Now().UTC())
	if req.Status == "open" {
		resolvedBy, resolvedAt = nil, nil
	}
	// Close this report and, when resolving/dismissing, the other open reports on the same message.
	if _, err := tx.ExecContext(ctx, `
		UPDATE abuse_reports SET status = $2, resolution_note = NULLIF($3, ''), resolved_by = $4,
			resolved_at = $5, action_taken = NULLIF($6, '')
		WHERE id = $1 OR ($2 <> 'open' AND status = 'open' AND message_id IS NOT NULL AND message_id = $7)`,
		id, req.Status, strings.TrimSpace(req.Note), resolvedBy, resolvedAt, action, messageID); err != nil {
		h.deps.internalError(c, err, "update report")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "update report")
		return
	}

	if deleted != nil {
		notifyMessageDeleted(ctx, h.deps, deleted)
	}
	if suspended {
		h.deps.Hub().SendToUsers([]uuid.UUID{*reportedUser}, "account.suspended", gin.H{})
		if err := revokeSessions(ctx, h.deps, *reportedUser, suspendedGeneration); err != nil {
			h.deps.Logger.WithError(err).Error("Failed to revoke sessions of suspended user")
		}
	}

	recordAudit(ctx, h.deps, c, adminID, "update", "abuse_report", id,
		gin.H{"status": req.Status, "actions": actions, "note": req.Note})
	c.JSON(http.StatusOK, gin.H{"id": id, "status": req.Status, "action_taken": action})
}

// deletedMessage identifies a soft-deleted message's conversation, for notifications.
type deletedMessage struct {
	ID       uuid.UUID
	Sender   uuid.UUID
	Receiver *uuid.UUID
	Group    *uuid.UUID
	Parent   *uuid.UUID
}

// softDeleteMessage marks a message deleted inside tx.
func softDeleteMessage(ctx context.Context, tx *sql.Tx, id uuid.UUID) (*deletedMessage, error) {
	d := &deletedMessage{ID: id}
	err := tx.QueryRowContext(ctx, `
		UPDATE messages SET is_deleted = true, deleted_at = NOW() WHERE id = $1
		RETURNING sender_id, receiver_id, group_id, parent_id`, id).Scan(&d.Sender, &d.Receiver, &d.Group, &d.Parent)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// notifyMessageDeleted tells everyone in the conversation that a message was deleted.
func notifyMessageDeleted(ctx context.Context, deps *Dependencies, d *deletedMessage) {
	recipients := []uuid.UUID{d.Sender}
	if d.Group != nil {
		recipients, _ = groupMemberIDs(ctx, deps.DB, *d.Group)
	} else if d.Receiver != nil {
		recipients = append(recipients, *d.Receiver)
	}
	deps.Hub().SendToUsers(recipients, "message.deleted", gin.H{"id": d.ID, "group_id": d.Group, "parent_id": d.Parent})
}

// ---------- audit log ----------

type auditEntry struct {
	ID           uuid.UUID       `json:"id"`
	Actor        *models.UserDTO `json:"actor,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *uuid.UUID      `json:"resource_id,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
	IPAddress    string          `json:"ip_address,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// ListAudit returns recent audit log entries, newest first.
func (h *AdminHandler) ListAudit(c *gin.Context) {
	company, _, ok := h.scope(c)
	if !ok {
		return
	}
	limit, offset := paging(c)
	ctx := c.Request.Context()
	rows, err := h.deps.DB.QueryContext(ctx, `
		SELECT a.id, a.user_id, a.action::text, COALESCE(a.resource_type, ''), a.resource_id,
			COALESCE(a.new_values::text, 'null'), COALESCE(host(a.ip_address), ''), a.created_at,
			COUNT(*) OVER ()
		FROM audit_logs a
		WHERE $3::uuid IS NULL OR a.user_id IN (SELECT id FROM users WHERE company_id = $3)
		ORDER BY a.created_at DESC
		LIMIT $1 OFFSET $2`, limit, offset, company)
	if err != nil {
		h.deps.internalError(c, err, "list audit log")
		return
	}
	var entries []auditEntry
	var actors []*uuid.UUID
	userIDs := map[uuid.UUID]bool{}
	total := 0
	for rows.Next() {
		var e auditEntry
		var actor *uuid.UUID
		var details string
		if err := rows.Scan(&e.ID, &actor, &e.Action, &e.ResourceType, &e.ResourceID, &details,
			&e.IPAddress, &e.CreatedAt, &total); err != nil {
			rows.Close()
			h.deps.internalError(c, err, "scan audit log")
			return
		}
		e.Details = json.RawMessage(details)
		if actor != nil {
			userIDs[*actor] = true
		}
		entries = append(entries, e)
		actors = append(actors, actor)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list audit log")
		return
	}
	users, err := loadUserDTOs(ctx, h.deps.DB, userIDs)
	if err != nil {
		h.deps.internalError(c, err, "load audit users")
		return
	}
	for i := range entries {
		if actors[i] != nil {
			entries[i].Actor = users[*actors[i]]
		}
	}
	if entries == nil {
		entries = []auditEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries, "total": total, "limit": limit, "offset": offset})
}
