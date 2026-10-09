package models

import (
	"time"

	"github.com/google/uuid"
)

// Group represents a group in the system
type Group struct {
	ID          uuid.UUID `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	GroupType   string    `db:"group_type" json:"group_type"` // team, project, channel, direct
	OwnerID     uuid.UUID `db:"owner_id" json:"owner_id"`
	CompanyID   uuid.UUID `db:"company_id" json:"company_id"`
	AvatarURL   string    `db:"avatar_url" json:"avatar_url"`
	IsEncrypted bool      `db:"is_encrypted" json:"is_encrypted"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time `db:"deleted_at" json:"deleted_at"`
}

// GroupMember represents a group member
type GroupMember struct {
	ID        uuid.UUID `db:"id" json:"id"`
	GroupID   uuid.UUID `db:"group_id" json:"group_id"`
	UserID    uuid.UUID `db:"user_id" json:"user_id"`
	Role      string    `db:"role" json:"role"` // admin, moderator, member
	JoinedAt  time.Time `db:"joined_at" json:"joined_at"`
}

// CreateGroupRequest represents a create group request
type CreateGroupRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=255"`
	Description string `json:"description" binding:"max=1000"`
	// "channel": open to everyone in the company; "team" and "project": private groups.
	GroupType   string `json:"group_type" binding:"required,oneof=team project channel"`
	AvatarURL   string `json:"avatar_url"`
	IsEncrypted *bool  `json:"is_encrypted"` // defaults to true when omitted
}

// UpdateGroupRequest represents an update group request
type UpdateGroupRequest struct {
	Name        string `json:"name" binding:"omitempty,min=1,max=255"`
	Description string `json:"description" binding:"omitempty,max=1000"`
	AvatarURL   string `json:"avatar_url"`
}

// AddMemberRequest represents an add member request
type AddMemberRequest struct {
	UserID uuid.UUID `json:"user_id" binding:"required"`
	Role   string    `json:"role" binding:"required,oneof=admin moderator member"`
}

// GroupDTO represents a group data transfer object
type GroupDTO struct {
	ID          uuid.UUID      `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	GroupType   string         `json:"group_type"`
	Category    string         `json:"category"` // channel | group
	IsMember    bool           `json:"is_member"`
	Owner       *UserDTO       `json:"owner"`
	AvatarURL   string         `json:"avatar_url"`
	IsEncrypted bool           `json:"is_encrypted"`
	MemberCount int            `json:"member_count"`
	Members     []GroupMemberDTO `json:"members,omitempty"`
	UnreadCount  int             `json:"unread_count"`
	MentionCount int             `json:"mention_count"`
	LastMessage  *MessageDTO     `json:"last_message,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// GroupMemberDTO represents a group member data transfer object
type GroupMemberDTO struct {
	ID       uuid.UUID `json:"id"`
	User     *UserDTO  `json:"user"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

// GroupListResponse represents a list of groups
type GroupListResponse struct {
	Groups []GroupDTO `json:"groups"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

// GroupSearchRequest represents a group search request
type GroupSearchRequest struct {
	Query  string `form:"q" binding:"required,min=1"`
	Limit  int    `form:"limit" binding:"omitempty,max=50"`
	Offset int    `form:"offset" binding:"omitempty,min=0"`
}

// GroupSearchResult represents group search results
type GroupSearchResult struct {
	Groups []GroupDTO `json:"groups"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

// RemoveMemberRequest represents a remove member request
type RemoveMemberRequest struct {
	UserID uuid.UUID `json:"user_id" binding:"required"`
}

// UpdateMemberRoleRequest represents an update member role request
type UpdateMemberRoleRequest struct {
	Role string `json:"role" binding:"required,oneof=admin moderator member"`
}

// LeaveGroupRequest represents a leave group request
type LeaveGroupRequest struct {
	Reason string `json:"reason"`
}

// Helper functions

// Category is how the group is shown: "channel" (open to the company) or "group" (private).
func (g *Group) Category() string {
	if g.GroupType == "channel" {
		return "channel"
	}
	return "group"
}

// ToDTO converts a Group to GroupDTO
func (g *Group) ToDTO(owner *User, memberCount int) *GroupDTO {
	return &GroupDTO{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		GroupType:   g.GroupType,
		Category:    g.Category(),
		IsMember:    true,
		Owner:       owner.ToDTO(),
		AvatarURL:   g.AvatarURL,
		IsEncrypted: g.IsEncrypted,
		MemberCount: memberCount,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
}

// MemberToDTO converts a GroupMember to GroupMemberDTO
func (gm *GroupMember) ToDTO(user *User) *GroupMemberDTO {
	return &GroupMemberDTO{
		ID:       gm.ID,
		User:     user.ToDTO(),
		Role:     gm.Role,
		JoinedAt: gm.JoinedAt,
	}
}

// IsAdmin checks if member is admin
func (gm *GroupMember) IsAdmin() bool {
	return gm.Role == "admin"
}

// IsModerator checks if member is moderator
func (gm *GroupMember) IsModerator() bool {
	return gm.Role == "moderator" || gm.Role == "admin"
}

// CanManageGroup checks if member can manage group
func (gm *GroupMember) CanManageGroup() bool {
	return gm.IsAdmin()
}

// CanEditMessages checks if member can edit messages
func (gm *GroupMember) CanEditMessages() bool {
	return gm.IsModerator()
}

// CanDeleteMessages checks if member can delete messages
func (gm *GroupMember) CanDeleteMessages() bool {
	return gm.IsModerator()
}

// CanRemoveMembers checks if member can remove members
func (gm *GroupMember) CanRemoveMembers() bool {
	return gm.IsModerator()
}
