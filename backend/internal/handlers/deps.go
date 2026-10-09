package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/bintalk/bintalk-clone/internal/config"
	"github.com/bintalk/bintalk-clone/internal/models"
	"github.com/bintalk/bintalk-clone/internal/services"
	"github.com/bintalk/bintalk-clone/pkg/chapa"
	"github.com/bintalk/bintalk-clone/pkg/kafka"
	"github.com/bintalk/bintalk-clone/pkg/mail"
	"github.com/bintalk/bintalk-clone/pkg/vault"
)

// Dependencies holds the shared services handlers need.
type Dependencies struct {
	Config            *config.Config
	DB                *sql.DB
	Redis             *redis.Client
	Kafka             *kafka.Producer
	Logger            *logrus.Logger
	VaultClient       *vault.VaultClient
	EncryptionService *services.EncryptionService
	Mailer            *mail.Mailer
	Chapa             *chapa.Client

	hubOnce sync.Once
	hub     *Hub

	callsOnce sync.Once
	calls     *CallManager
}

// Calls returns the shared call manager.
func (d *Dependencies) Calls() *CallManager {
	d.callsOnce.Do(func() { d.calls = newCallManager(d) })
	return d.calls
}

// Hub returns the WebSocket hub shared by all handlers.
func (d *Dependencies) Hub() *Hub {
	d.hubOnce.Do(func() {
		d.hub = newHub(d.Logger)
		d.hub.loadPreference = loadPresencePreference(d)
	})
	return d.hub
}

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

var errNotFound = errors.New("not found")

// queryer is satisfied by *sql.DB and *sql.Tx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// userColumns returns the users columns in the order scanUser expects, qualified by alias.
func userColumns(alias string) string {
	cols := []string{
		"id", "username", "email", "password_hash", "COALESCE(%s.full_name, '')", "COALESCE(%s.avatar_url, '')",
		"public_key", "COALESCE(%s.status, 'active')", "phone_encrypted", "phone_iv",
		"COALESCE(%s.mfa_enabled, false)", "last_login_at", "created_at", "updated_at", "deleted_at",
		"COALESCE(%s.role, 'user')", "COALESCE(%s.must_change_password, false)", "session_generation", "company_id", "company_role",
	}
	for i, col := range cols {
		if strings.Contains(col, "%s") {
			cols[i] = strings.ReplaceAll(col, "%s", alias)
		} else {
			cols[i] = alias + "." + col
		}
	}
	return strings.Join(cols, ", ")
}

// userScanDest returns scan destinations matching userColumns.
func userScanDest(u *models.User) []interface{} {
	return []interface{}{
		&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.FullName, &u.AvatarURL,
		&u.PublicKey, &u.Status, &u.PhoneEncrypted, &u.PhoneIV,
		&u.MFAEnabled, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
		&u.Role, &u.MustChangePassword, &u.SessionGeneration, &u.CompanyID, &u.CompanyRole,
	}
}

func scanUser(row rowScanner, extra ...interface{}) (*models.User, error) {
	var u models.User
	if err := row.Scan(append(userScanDest(&u), extra...)...); err != nil {
		return nil, err
	}
	return &u, nil
}

// loadUser fetches a user by ID, including soft-deleted users. It returns errNotFound if absent.
func loadUser(ctx context.Context, db *sql.DB, id uuid.UUID) (*models.User, error) {
	u, err := scanUser(db.QueryRowContext(ctx, "SELECT "+userColumns("u")+" FROM users u WHERE u.id = $1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return u, err
}

// loadUserDTOs loads full user DTOs (including email and role) by ID. Strip private fields
// with publicUserDTO-style filtering before sending them to anyone but the user or an admin.
func loadUserDTOs(ctx context.Context, db *sql.DB, ids map[uuid.UUID]bool) (map[uuid.UUID]*models.UserDTO, error) {
	out := map[uuid.UUID]*models.UserDTO{}
	if len(ids) == 0 {
		return out, nil
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id.String())
	}
	rows, err := db.QueryContext(ctx, "SELECT "+userColumns("u")+" FROM users u WHERE u.id = ANY($1)", pq.Array(list))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out[u.ID] = u.ToDTO()
	}
	return out, rows.Err()
}

// publicUserDTO hides the email address, role and password state unless the viewer is the
// user themselves.
func publicUserDTO(u *models.User, viewer uuid.UUID) *models.UserDTO {
	dto := u.ToDTO()
	if u.ID != viewer {
		dto.Email = ""
		dto.Role = ""
		dto.MustChangePassword = false
	}
	return dto
}

// paging reads limit/offset query parameters with sane defaults and bounds.
func paging(c *gin.Context) (limit, offset int) {
	limit, err := strconv.Atoi(c.Query("limit"))
	if err != nil || limit <= 0 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	offset, err = strconv.Atoi(c.Query("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}
	return limit, offset
}

// uuidParam parses a UUID path parameter, writing a 400 response if it is invalid.
func uuidParam(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid " + name})
		return uuid.Nil, false
	}
	return id, true
}

func badRequest(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
}

func (d *Dependencies) internalError(c *gin.Context, err error, action string) {
	if errors.Is(err, context.Canceled) {
		// The client went away (closed tab, navigated, aborted fetch); nothing failed on our side.
		d.Logger.WithField("path", c.Request.URL.Path).Debugf("%s: client disconnected", action)
		c.AbortWithStatus(499)
		return
	}
	d.Logger.WithError(err).WithField("path", c.Request.URL.Path).Error(action)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

// escapeLike escapes LIKE wildcards so user input is matched literally.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
