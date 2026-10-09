package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a system user
type User struct {
	ID              uuid.UUID `db:"id" json:"id"`
	Username        string    `db:"username" json:"username"`
	Email           string    `db:"email" json:"email"`
	PasswordHash    string    `db:"password_hash" json:"-"`
	FullName        string    `db:"full_name" json:"full_name"`
	AvatarURL       string    `db:"avatar_url" json:"avatar_url"`
	PublicKey       string    `db:"public_key" json:"public_key"`
	Status          string    `db:"status" json:"status"` // active, inactive, suspended, deleted
	PhoneEncrypted  []byte    `db:"phone_encrypted" json:"-"`
	PhoneIV         []byte    `db:"phone_iv" json:"-"`
	MFAEnabled      bool      `db:"mfa_enabled" json:"mfa_enabled"`
	LastLoginAt     *time.Time `db:"last_login_at" json:"last_login_at"`
	CreatedAt       time.Time `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time `db:"updated_at" json:"updated_at"`
	DeletedAt       *time.Time `db:"deleted_at" json:"deleted_at"`
	Role               string `db:"role" json:"role"` // user, admin
	MustChangePassword bool   `db:"must_change_password" json:"must_change_password"`
	// SessionGeneration changes whenever all of the user's sessions must end (see middleware.Session).
	SessionGeneration int64 `db:"session_generation" json:"-"`
	CompanyID         uuid.UUID `json:"company_id"`
	CompanyRole       string    `json:"company_role"` // owner, admin, member
}

// IsCompanyAdmin reports whether the user manages their company (owner or admin).
func (u *User) IsCompanyAdmin() bool {
	return u.CompanyRole == CompanyOwner || u.CompanyRole == CompanyAdmin
}

// IsAdmin reports whether the user has the admin role.
func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

// UserPreferences represents user preferences
type UserPreferences struct {
	ID                   uuid.UUID `db:"id" json:"id"`
	UserID               uuid.UUID `db:"user_id" json:"user_id"`
	Language             string    `db:"language" json:"language"`
	Timezone             string    `db:"timezone" json:"timezone"`
	NotificationsEnabled bool      `db:"notifications_enabled" json:"notifications_enabled"`
	EmailNotifications   bool      `db:"email_notifications" json:"email_notifications"`
	PushNotifications    bool      `db:"push_notifications" json:"push_notifications"`
	Theme                string    `db:"theme" json:"theme"`
	TwoFactorEnabled     bool      `db:"two_factor_enabled" json:"two_factor_enabled"`
	CreatedAt            time.Time `db:"created_at" json:"created_at"`
	UpdatedAt            time.Time `db:"updated_at" json:"updated_at"`
}

// UserSession represents an active user session
type UserSession struct {
	ID              uuid.UUID `db:"id" json:"id"`
	UserID          uuid.UUID `db:"user_id" json:"user_id"`
	RefreshTokenHash string    `db:"refresh_token_hash" json:"-"`
	ExpiresAt       time.Time `db:"expires_at" json:"expires_at"`
	IPAddress       string    `db:"ip_address" json:"ip_address"`
	UserAgent       string    `db:"user_agent" json:"user_agent"`
	CreatedAt       time.Time `db:"created_at" json:"created_at"`
	LastActivity    time.Time `db:"last_activity" json:"last_activity"`
}

// RegisterRequest creates an account from an invitation (InviteToken from the invitation link).
type RegisterRequest struct {
	InviteToken string `json:"invite_token" binding:"required"`
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	FullName string `json:"full_name" binding:"required,max=255"`
	// PublicKey is a client public key stored for future use (optional)
	PublicKey string `json:"public_key" binding:"max=8192"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	User         *UserDTO `json:"user"`
	Company      *Company `json:"company,omitempty"`
}

// UserDTO is a data transfer object for user
type UserDTO struct {
	ID        uuid.UUID `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	AvatarURL string    `json:"avatar_url"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	// Only included for the user themselves (and admins).
	Role               string `json:"role,omitempty"`
	MustChangePassword bool   `json:"must_change_password,omitempty"`

	CompanyID   uuid.UUID `json:"company_id"`
	CompanyRole string    `json:"company_role,omitempty"`
}

// UpdateUserRequest represents a user update request
type UpdateUserRequest struct {
	FullName  string `json:"full_name"`
	AvatarURL string `json:"avatar_url"`
	Phone     string `json:"phone"`
	Timezone  string `json:"timezone"`
	Language  string `json:"language"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=72"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// MFASetupRequest represents MFA setup
type MFASetupRequest struct {
	Password string `json:"password" binding:"required"`
}

// MFAVerifyRequest represents MFA verification
type MFAVerifyRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

// UserSearchQuery represents a user search query
type UserSearchQuery struct {
	Query  string `form:"q" binding:"required,min=1"`
	Limit  int    `form:"limit" binding:"omitempty,max=50"`
	Offset int    `form:"offset" binding:"omitempty,min=0"`
}

// UserSearchResult represents search results
type UserSearchResult struct {
	Users      []UserDTO `json:"users"`
	Total      int       `json:"total"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset"`
}

// Helper functions

// ToDTO converts a User to UserDTO
func (u *User) ToDTO() *UserDTO {
	return &UserDTO{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		FullName:  u.FullName,
		AvatarURL: u.AvatarURL,
		Status:    u.Status,
		CreatedAt: u.CreatedAt,

		Role:               u.Role,
		MustChangePassword: u.MustChangePassword,
		CompanyID:          u.CompanyID,
		CompanyRole:        u.CompanyRole,
	}
}

// IsActive checks if user is active
func (u *User) IsActive() bool {
	return u.Status == "active" && u.DeletedAt == nil
}

// IsSuspended checks if user is suspended
func (u *User) IsSuspended() bool {
	return u.Status == "suspended"
}

// IsDeleted checks if user is deleted
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}
