package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

// UserHandler handles user profiles and search.
type UserHandler struct {
	deps *Dependencies
}

// NewUserHandler creates a UserHandler.
func NewUserHandler(deps *Dependencies) *UserHandler {
	return &UserHandler{deps: deps}
}

// userProfile is a user plus the public key other users need for end-to-end encryption.
type userProfile struct {
	*models.UserDTO
	PublicKey string `json:"public_key"`
}

// GetUser returns a profile of someone in the caller's company. Email is only included for the
// caller's own profile.
func (h *UserHandler) GetUser(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	me, ok := currentActor(c, h.deps)
	if !ok {
		return
	}

	user, err := loadColleague(c.Request.Context(), h.deps.DB, me.CompanyID, id)
	if errors.Is(err, errNotFound) || (err == nil && user.IsDeleted()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": userProfile{
		UserDTO:   publicUserDTO(user, middleware.GetUserID(c)),
		PublicKey: user.PublicKey,
	}})
}

// UpdateUser updates the caller's own profile and preferences. Empty fields are left unchanged.
func (h *UserHandler) UpdateUser(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	if id != middleware.GetUserID(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only update your own profile"})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if len(req.FullName) > 255 || len(req.Timezone) > 50 || len(req.Language) > 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "full_name, timezone or language is too long"})
		return
	}

	// Phone numbers are stored encrypted (ciphertext with GCM tag appended, plus IV).
	var phoneCiphertext, phoneIV, phoneKeyVersion interface{}
	if phone := strings.TrimSpace(req.Phone); phone != "" {
		ciphertext, iv, tag, version, err := h.deps.EncryptionService.EncryptField([]byte(phone))
		if err != nil {
			h.deps.internalError(c, err, "encrypt phone")
			return
		}
		phoneCiphertext, phoneIV, phoneKeyVersion = append(ciphertext, tag...), iv, version
	}

	ctx := c.Request.Context()
	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()

	user, err := scanUser(tx.QueryRowContext(ctx, `
		UPDATE users AS u SET
			full_name       = COALESCE(NULLIF($2, ''), u.full_name),
			avatar_url      = COALESCE(NULLIF($3, ''), u.avatar_url),
			phone_encrypted = COALESCE($4, u.phone_encrypted),
			phone_iv        = COALESCE($5, u.phone_iv),
			phone_key_version = COALESCE($6, u.phone_key_version)
		WHERE u.id = $1 AND u.deleted_at IS NULL
		RETURNING `+userColumns("u"),
		id, strings.TrimSpace(req.FullName), strings.TrimSpace(req.AvatarURL), phoneCiphertext, phoneIV, phoneKeyVersion,
	))
	if err != nil {
		h.deps.internalError(c, err, "update user")
		return
	}

	if req.Timezone != "" || req.Language != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_preferences AS p (user_id, timezone, language)
			VALUES ($1, COALESCE(NULLIF($2, ''), 'UTC'), COALESCE(NULLIF($3, ''), 'en'))
			ON CONFLICT (user_id) DO UPDATE SET
				timezone = COALESCE(NULLIF($2, ''), p.timezone),
				language = COALESCE(NULLIF($3, ''), p.language)`,
			id, req.Timezone, req.Language,
		); err != nil {
			h.deps.internalError(c, err, "update preferences")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "commit user update")
		return
	}

	h.deps.Kafka.Publish(ctx, "user.updated", id.String(), gin.H{"user_id": id})
	c.JSON(http.StatusOK, gin.H{"user": userProfile{UserDTO: user.ToDTO(), PublicKey: user.PublicKey}})
}

// SearchUsers finds active people in the caller's company by username or full name
// (GET /users/search?q=...).
func (h *UserHandler) SearchUsers(c *gin.Context) {
	me, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	var query models.UserSearchQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		badRequest(c, err)
		return
	}
	limit, offset := paging(c)
	pattern := "%" + escapeLike(strings.TrimSpace(query.Query)) + "%"

	rows, err := h.deps.DB.QueryContext(c.Request.Context(), `
		SELECT `+userColumns("u")+`, COUNT(*) OVER ()
		FROM users u
		WHERE u.deleted_at IS NULL AND u.status = 'active' AND u.company_id = $4
		  AND (u.username ILIKE $1 OR u.full_name ILIKE $1)
		ORDER BY u.username
		LIMIT $2 OFFSET $3`, pattern, limit, offset, me.CompanyID)
	if err != nil {
		h.deps.internalError(c, err, "search users")
		return
	}
	defer rows.Close()

	viewer := middleware.GetUserID(c)
	result := models.UserSearchResult{Users: []models.UserDTO{}, Limit: limit, Offset: offset}
	for rows.Next() {
		user, err := scanUser(rows, &result.Total)
		if err != nil {
			h.deps.internalError(c, err, "scan user")
			return
		}
		result.Users = append(result.Users, *publicUserDTO(user, viewer))
	}
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "search users")
		return
	}

	c.JSON(http.StatusOK, result)
}
