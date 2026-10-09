package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	userIDKey  = "user_id"
	sessionKey = "session"

	// passwordChangeFlag is appended to a session's Redis value when the user must change
	// their password before doing anything else.
	passwordChangeFlag = "pwchange"

	// sessionGenerationTTL bounds how long a cached users.session_generation is trusted. Revocation
	// overwrites the cache immediately; the TTL only matters if that write fails.
	sessionGenerationTTL = 30 * time.Second
)

// ErrInvalidToken is returned when an access token is unknown or expired.
var ErrInvalidToken = errors.New("invalid or expired token")

// Paths a session that must change its password may still use.
var passwordChangeAllowed = map[string]bool{
	"/api/v1/auth/change-password": true,
	"/api/v1/auth/me":              true,
	"/api/v1/auth/logout":          true,
}

// Session is what an access token resolves to.
type Session struct {
	UserID uuid.UUID
	// Generation is users.session_generation when the session was issued. Changing a password,
	// resetting it or suspending the account increments the user's generation, which invalidates
	// every session issued before, even one issued concurrently with the change.
	Generation         int64
	MustChangePassword bool
}

// AccessTokenKey returns the Redis key under which an access token's session is stored.
// Only a hash of the token is stored, so a Redis dump does not expose usable tokens.
func AccessTokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "auth:token:" + hex.EncodeToString(sum[:])
}

// UserTokensKey is the Redis set of a user's access token keys, used to revoke all sessions.
func UserTokensKey(userID uuid.UUID) string {
	return "auth:user:" + userID.String()
}

// SessionGenerationKey is the Redis key caching a user's current session generation.
func SessionGenerationKey(userID uuid.UUID) string {
	return "auth:gen:" + userID.String()
}

// SessionValue encodes a session for storage in Redis: "<user id>:g<generation>[:pwchange]".
func SessionValue(userID uuid.UUID, generation int64, mustChangePassword bool) string {
	value := userID.String() + ":g" + strconv.FormatInt(generation, 10)
	if mustChangePassword {
		value += ":" + passwordChangeFlag
	}
	return value
}

// parseSessionValue decodes SessionValue. Values written before generations existed
// ("<id>" or "<id>:pwchange") decode with generation 0.
func parseSessionValue(value string) (Session, bool) {
	parts := strings.Split(value, ":")
	id, err := uuid.Parse(parts[0])
	if err != nil {
		return Session{}, false
	}
	session := Session{UserID: id}
	for _, part := range parts[1:] {
		switch {
		case part == passwordChangeFlag:
			session.MustChangePassword = true
		case strings.HasPrefix(part, "g"):
			gen, err := strconv.ParseInt(part[1:], 10, 64)
			if err != nil {
				return Session{}, false
			}
			session.Generation = gen
		default:
			return Session{}, false
		}
	}
	return session, true
}

// LookupSession resolves an access token.
func LookupSession(ctx context.Context, rdb *redis.Client, db *sql.DB, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrInvalidToken
	}
	return LookupSessionByKey(ctx, rdb, db, AccessTokenKey(token))
}

// LookupSessionByKey resolves a session from its Redis key (see AccessTokenKey). The session is
// valid only while its generation matches the user's current one.
func LookupSessionByKey(ctx context.Context, rdb *redis.Client, db *sql.DB, key string) (Session, error) {
	value, err := rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrInvalidToken
	}
	if err != nil {
		return Session{}, err
	}
	session, ok := parseSessionValue(value)
	if !ok {
		return Session{}, ErrInvalidToken
	}
	current, err := CurrentSessionGeneration(ctx, rdb, db, session.UserID)
	if err != nil {
		return Session{}, err
	}
	if current != session.Generation {
		return Session{}, ErrInvalidToken
	}
	return session, nil
}

// CurrentSessionGeneration returns users.session_generation, cached in Redis for a short time.
// It fails closed: if neither Redis nor the database answers, it returns an error. A user that
// no longer exists gets generation -1, which matches no session.
func CurrentSessionGeneration(ctx context.Context, rdb *redis.Client, db *sql.DB, userID uuid.UUID) (int64, error) {
	key := SessionGenerationKey(userID)
	gen, err := rdb.Get(ctx, key).Int64()
	if err == nil {
		return gen, nil
	}
	if !errors.Is(err, redis.Nil) {
		return 0, err
	}
	err = db.QueryRowContext(ctx,
		`SELECT session_generation FROM users WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&gen)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, nil
	}
	if err != nil {
		return 0, err
	}
	// SetNX: if a revocation stored a newer generation meanwhile, keep it.
	rdb.SetNX(ctx, key, gen, sessionGenerationTTL)
	return gen, nil
}

// StoreSessionGeneration records a user's new generation after it was incremented in the
// database, so the change takes effect immediately rather than after sessionGenerationTTL.
func StoreSessionGeneration(ctx context.Context, rdb *redis.Client, userID uuid.UUID, generation int64) error {
	return rdb.Set(ctx, SessionGenerationKey(userID), generation, sessionGenerationTTL).Err()
}

// BearerToken extracts the token from an "Authorization: Bearer <token>" header.
func BearerToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// AuthMiddleware requires a valid access token and stores the caller's user ID in the context.
// Sessions that must change their password can only reach the change-password endpoints.
func AuthMiddleware(rdb *redis.Client, db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := BearerToken(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		session, err := LookupSession(c.Request.Context(), rdb, db, token)
		if errors.Is(err, ErrInvalidToken) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, context.Canceled) {
			c.AbortWithStatus(499) // client went away mid-request
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "authentication unavailable"})
			return
		}
		if session.MustChangePassword && !passwordChangeAllowed[c.Request.URL.Path] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "you must change your password before continuing",
				"code":  "password_change_required",
			})
			return
		}

		c.Set(userIDKey, session.UserID)
		c.Set(sessionKey, session)
		c.Next()
	}
}

// RequireAdmin allows only users with the admin role (checked against the database on every
// request, so revoking the role takes effect immediately). Use after AuthMiddleware.
func RequireAdmin(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var isAdmin bool
		err := db.QueryRowContext(c.Request.Context(), `
			SELECT COALESCE(role, 'user') = 'admin' AND status = 'active' AND deleted_at IS NULL
			FROM users WHERE id = $1`, GetUserID(c)).Scan(&isAdmin)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "authorization unavailable"})
			return
		}
		if !isAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			return
		}
		c.Next()
	}
}

// GetSession returns the authenticated session. It must only be used behind AuthMiddleware.
func GetSession(c *gin.Context) Session {
	if v, ok := c.Get(sessionKey); ok {
		if s, ok := v.(Session); ok {
			return s
		}
	}
	return Session{}
}

// GetUserID returns the authenticated user's ID. It must only be used behind AuthMiddleware.
func GetUserID(c *gin.Context) uuid.UUID {
	if id, ok := c.Get(userIDKey); ok {
		if userID, ok := id.(uuid.UUID); ok {
			return userID
		}
	}
	return uuid.Nil
}
