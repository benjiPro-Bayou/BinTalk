package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

const groupColumns = `g.id, g.name, COALESCE(g.description, ''), g.group_type, g.owner_id,
	COALESCE(g.avatar_url, ''), COALESCE(g.is_encrypted, true), g.created_at, g.updated_at, g.deleted_at, g.company_id`

// GroupHandler handles group management.
type GroupHandler struct {
	deps *Dependencies
}

// NewGroupHandler creates a GroupHandler.
func NewGroupHandler(deps *Dependencies) *GroupHandler {
	return &GroupHandler{deps: deps}
}

func scanGroup(row rowScanner) (*models.Group, error) {
	var g models.Group
	err := row.Scan(&g.ID, &g.Name, &g.Description, &g.GroupType, &g.OwnerID,
		&g.AvatarURL, &g.IsEncrypted, &g.CreatedAt, &g.UpdatedAt, &g.DeletedAt, &g.CompanyID)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// loadGroup fetches a non-deleted group, returning errNotFound if absent.
func loadGroup(ctx context.Context, db *sql.DB, id uuid.UUID) (*models.Group, error) {
	g, err := scanGroup(db.QueryRowContext(ctx,
		"SELECT "+groupColumns+" FROM groups g WHERE g.id = $1 AND g.deleted_at IS NULL", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return g, err
}

// loadMembership returns the user's membership in a group, or errNotFound if they are not a member.
func loadMembership(ctx context.Context, db *sql.DB, groupID, userID uuid.UUID) (*models.GroupMember, error) {
	var m models.GroupMember
	err := db.QueryRowContext(ctx, `
		SELECT id, group_id, user_id, COALESCE(role, 'member'), joined_at
		FROM group_members WHERE group_id = $1 AND user_id = $2`, groupID, userID,
	).Scan(&m.ID, &m.GroupID, &m.UserID, &m.Role, &m.JoinedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return &m, err
}

// groupMemberIDs returns the IDs of all members of a group.
func groupMemberIDs(ctx context.Context, db *sql.DB, groupID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `SELECT user_id FROM group_members WHERE group_id = $1`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// groupMembers returns all members of a group with their user records.
func (h *GroupHandler) groupMembers(ctx context.Context, groupID, viewer uuid.UUID) ([]models.GroupMemberDTO, error) {
	rows, err := h.deps.DB.QueryContext(ctx, `
		SELECT gm.id, gm.group_id, gm.user_id, COALESCE(gm.role, 'member'), gm.joined_at, `+userColumns("u")+`
		FROM group_members gm
		JOIN users u ON u.id = gm.user_id
		WHERE gm.group_id = $1
		ORDER BY gm.joined_at`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := []models.GroupMemberDTO{}
	for rows.Next() {
		var m models.GroupMember
		var u models.User
		err := rows.Scan(append([]interface{}{&m.ID, &m.GroupID, &m.UserID, &m.Role, &m.JoinedAt},
			userScanDest(&u)...)...)
		if err != nil {
			return nil, err
		}
		dto := m.ToDTO(&u)
		dto.User = publicUserDTO(&u, viewer)
		members = append(members, *dto)
	}
	return members, rows.Err()
}

// groupDTO builds the full group representation including owner and members.
func (h *GroupHandler) groupDTO(ctx context.Context, g *models.Group, viewer uuid.UUID) (*models.GroupDTO, error) {
	owner, err := loadUser(ctx, h.deps.DB, g.OwnerID)
	if err != nil {
		return nil, err
	}
	members, err := h.groupMembers(ctx, g.ID, viewer)
	if err != nil {
		return nil, err
	}
	dto := g.ToDTO(owner, len(members))
	dto.Owner = publicUserDTO(owner, viewer)
	dto.Members = members
	return dto, nil
}

// CreateGroup creates a group with the caller as its admin.
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var req models.CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	isEncrypted := true
	if req.IsEncrypted != nil {
		isEncrypted = *req.IsEncrypted
	}

	ctx := c.Request.Context()
	me, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	userID := me.ID

	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()

	group, err := scanGroup(tx.QueryRowContext(ctx, `
		INSERT INTO groups AS g (name, description, group_type, owner_id, avatar_url, is_encrypted, company_id)
		VALUES ($1, NULLIF($2, ''), $3, $4, NULLIF($5, ''), $6, $7)
		RETURNING `+groupColumns,
		strings.TrimSpace(req.Name), strings.TrimSpace(req.Description), req.GroupType, userID,
		strings.TrimSpace(req.AvatarURL), isEncrypted, me.CompanyID,
	))
	if err != nil {
		h.deps.internalError(c, err, "create group")
		return
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'admin')`, group.ID, userID,
	); err != nil {
		h.deps.internalError(c, err, "add group owner")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "commit group")
		return
	}

	dto, err := h.groupDTO(ctx, group, userID)
	if err != nil {
		h.deps.internalError(c, err, "load group")
		return
	}

	h.deps.Kafka.Publish(ctx, "group.created", group.ID.String(), gin.H{"group_id": group.ID, "owner_id": userID})
	c.JSON(http.StatusCreated, gin.H{"group": dto})
}

// ListGroups returns the caller's groups with unread and unread-mention counts and the latest
// message, most recently active first. Unread counts cover top-level messages since the caller
// joined; mentions also count thread replies.
func (h *GroupHandler) ListGroups(c *gin.Context) {
	userID := middleware.GetUserID(c)
	limit, offset := paging(c)

	rows, err := h.deps.DB.QueryContext(c.Request.Context(), `
		SELECT `+groupColumns+`, `+userColumns("o")+`,
			(SELECT COUNT(*) FROM group_members x WHERE x.group_id = g.id),
			(SELECT COUNT(*) FROM messages m
			 WHERE m.group_id = g.id AND m.parent_id IS NULL AND m.sender_id <> $1
			   AND NOT COALESCE(m.is_deleted, false) AND m.created_at >= gm.joined_at
			   AND NOT EXISTS (SELECT 1 FROM message_reads r WHERE r.message_id = m.id AND r.user_id = $1)),
			(SELECT COUNT(*) FROM messages m
			 JOIN message_mentions mm ON mm.message_id = m.id AND mm.user_id = $1
			 WHERE m.group_id = g.id AND NOT COALESCE(m.is_deleted, false)
			   AND NOT EXISTS (SELECT 1 FROM message_reads r WHERE r.message_id = m.id AND r.user_id = $1)),
			COUNT(*) OVER ()
		FROM groups g
		JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = $1
		JOIN users o ON o.id = g.owner_id
		WHERE g.deleted_at IS NULL
		ORDER BY GREATEST(g.updated_at,
			COALESCE((SELECT MAX(m.created_at) FROM messages m WHERE m.group_id = g.id), g.updated_at)) DESC
		LIMIT $2 OFFSET $3`, userID, limit, offset)
	if err != nil {
		h.deps.internalError(c, err, "list groups")
		return
	}
	defer rows.Close()

	result := models.GroupListResponse{Groups: []models.GroupDTO{}, Limit: limit, Offset: offset}
	for rows.Next() {
		var g models.Group
		var owner models.User
		var memberCount, unread, mentions int
		dest := []interface{}{&g.ID, &g.Name, &g.Description, &g.GroupType, &g.OwnerID,
			&g.AvatarURL, &g.IsEncrypted, &g.CreatedAt, &g.UpdatedAt, &g.DeletedAt, &g.CompanyID}
		dest = append(append(dest, userScanDest(&owner)...), &memberCount, &unread, &mentions, &result.Total)
		if err := rows.Scan(dest...); err != nil {
			h.deps.internalError(c, err, "scan group")
			return
		}
		dto := g.ToDTO(&owner, memberCount)
		dto.Owner = publicUserDTO(&owner, userID)
		dto.UnreadCount, dto.MentionCount = unread, mentions
		result.Groups = append(result.Groups, *dto)
	}
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list groups")
		return
	}
	rows.Close()

	// Latest top-level message per group, for the chat list preview, in one query.
	ctx := c.Request.Context()
	ids := make([]string, len(result.Groups))
	index := make(map[uuid.UUID]int, len(result.Groups))
	for i := range result.Groups {
		ids[i] = result.Groups[i].ID.String()
		index[result.Groups[i].ID] = i
	}
	if len(ids) > 0 {
		rows, err := h.deps.DB.QueryContext(ctx, `
			SELECT `+messageColumns+`, `+userColumns("u")+`
			FROM unnest($1::uuid[]) AS g(id)
			CROSS JOIN LATERAL (
				SELECT x.* FROM messages x
				WHERE x.group_id = g.id AND x.parent_id IS NULL AND NOT COALESCE(x.is_deleted, false)
				ORDER BY x.created_at DESC LIMIT 1) m
			JOIN users u ON u.id = m.sender_id`, pq.Array(ids))
		if err != nil {
			h.deps.internalError(c, err, "load last group messages")
			return
		}
		var previews []models.MessageDTO
		for rows.Next() {
			var sender models.User
			msg, err := scanMessage(rows, userScanDest(&sender)...)
			if err != nil {
				rows.Close()
				h.deps.internalError(c, err, "load last group messages")
				return
			}
			last := msg.ToDTO(&sender)
			last.Sender = publicUserDTO(&sender, userID)
			last.Content = decryptMessage(h.deps, msg)
			previews = append(previews, *last)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			h.deps.internalError(c, err, "load last group messages")
			return
		}
		_ = enrichMessages(ctx, h.deps.DB, previews)
		for i := range previews {
			last := previews[i]
			result.Groups[index[*last.GroupID]].LastMessage = &last
		}
	}

	c.JSON(http.StatusOK, result)
}

// GetGroup returns a group and its members. Only members can see a group.
func (h *GroupHandler) GetGroup(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)

	group, err := loadGroup(ctx, h.deps.DB, id)
	if err == nil {
		_, err = loadMembership(ctx, h.deps.DB, id, userID)
	}
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load group")
		return
	}

	dto, err := h.groupDTO(ctx, group, userID)
	if err != nil {
		h.deps.internalError(c, err, "load group")
		return
	}
	c.JSON(http.StatusOK, gin.H{"group": dto})
}

// UpdateGroup updates a group's name, description or avatar. Admins only.
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req models.UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}

	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	if !h.requireRole(c, id, userID, (*models.GroupMember).CanManageGroup, "only group admins can update the group") {
		return
	}

	group, err := scanGroup(h.deps.DB.QueryRowContext(ctx, `
		UPDATE groups AS g SET
			name        = COALESCE(NULLIF($2, ''), g.name),
			description = COALESCE(NULLIF($3, ''), g.description),
			avatar_url  = COALESCE(NULLIF($4, ''), g.avatar_url)
		WHERE g.id = $1 AND g.deleted_at IS NULL
		RETURNING `+groupColumns,
		id, strings.TrimSpace(req.Name), strings.TrimSpace(req.Description), strings.TrimSpace(req.AvatarURL),
	))
	if err != nil {
		h.deps.internalError(c, err, "update group")
		return
	}

	dto, err := h.groupDTO(ctx, group, userID)
	if err != nil {
		h.deps.internalError(c, err, "load group")
		return
	}

	if memberIDs, err := groupMemberIDs(ctx, h.deps.DB, id); err == nil {
		h.deps.Hub().SendToUsers(memberIDs, "group.updated", gin.H{"group_id": id})
	}
	h.deps.Kafka.Publish(ctx, "group.updated", id.String(), gin.H{"group_id": id, "updated_by": userID})
	c.JSON(http.StatusOK, gin.H{"group": dto})
}

// AddMember adds a user to a group. Moderators can add members; only admins can grant
// the admin or moderator role.
func (h *GroupHandler) AddMember(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req models.AddMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}

	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	requiredRole := (*models.GroupMember).IsModerator
	if req.Role != "member" {
		requiredRole = (*models.GroupMember).IsAdmin
	}
	if !h.requireRole(c, id, userID, requiredRole, "you do not have permission to add members with this role") {
		return
	}

	group, err := loadGroup(ctx, h.deps.DB, id)
	if err != nil {
		h.deps.internalError(c, err, "load group")
		return
	}
	// Only people from the group's company can be added.
	user, err := loadColleague(ctx, h.deps.DB, group.CompanyID, req.UserID)
	if errors.Is(err, errNotFound) || (err == nil && !user.IsActive()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}

	member := models.GroupMember{GroupID: id, UserID: req.UserID, Role: req.Role}
	err = h.deps.DB.QueryRowContext(ctx, `
		INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (group_id, user_id) DO NOTHING
		RETURNING id, joined_at`, id, req.UserID, req.Role,
	).Scan(&member.ID, &member.JoinedAt)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusConflict, gin.H{"error": "user is already a member"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "add member")
		return
	}

	dto := member.ToDTO(user)
	dto.User = publicUserDTO(user, userID)

	h.deps.Calls().addToGroupCalls(id, req.UserID)
	if memberIDs, err := groupMemberIDs(ctx, h.deps.DB, id); err == nil {
		h.deps.Hub().SendToUsers(memberIDs, "group.member_added", gin.H{"group_id": id, "member": dto})
	}
	h.deps.Kafka.Publish(ctx, "group.member_added", id.String(),
		gin.H{"group_id": id, "user_id": req.UserID, "role": req.Role, "added_by": userID})
	c.JSON(http.StatusCreated, gin.H{"member": dto})
}

// BrowseChannels lists the channels of the caller's company, including ones they have not
// joined (GET /channels).
func (h *GroupHandler) BrowseChannels(c *gin.Context) {
	me, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	rows, err := h.deps.DB.QueryContext(c.Request.Context(), `
		SELECT `+groupColumns+`,
			(SELECT COUNT(*) FROM group_members x WHERE x.group_id = g.id),
			EXISTS (SELECT 1 FROM group_members x WHERE x.group_id = g.id AND x.user_id = $2)
		FROM groups g
		WHERE g.company_id = $1 AND g.group_type = 'channel' AND g.deleted_at IS NULL
		ORDER BY lower(g.name)`, me.CompanyID, me.ID)
	if err != nil {
		h.deps.internalError(c, err, "list channels")
		return
	}
	defer rows.Close()
	channels := []models.GroupDTO{}
	for rows.Next() {
		var g models.Group
		var members int
		var isMember bool
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.GroupType, &g.OwnerID, &g.AvatarURL,
			&g.IsEncrypted, &g.CreatedAt, &g.UpdatedAt, &g.DeletedAt, &g.CompanyID, &members, &isMember); err != nil {
			h.deps.internalError(c, err, "scan channel")
			return
		}
		dto := g.ToDTO(&models.User{ID: g.OwnerID}, members)
		dto.Owner = nil
		dto.IsMember = isMember
		channels = append(channels, *dto)
	}
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list channels")
		return
	}
	c.JSON(http.StatusOK, gin.H{"channels": channels})
}

// JoinChannel adds the caller to a channel of their company (POST /groups/:id/join). Private
// groups can only be joined by being added.
func (h *GroupHandler) JoinChannel(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	me, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	group, err := loadGroup(ctx, h.deps.DB, id)
	if errors.Is(err, errNotFound) || (err == nil && (group.CompanyID != me.CompanyID || group.GroupType != "channel")) {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load channel")
		return
	}
	if _, err := h.deps.DB.ExecContext(ctx, `
		INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')
		ON CONFLICT (group_id, user_id) DO NOTHING`, id, me.ID); err != nil {
		h.deps.internalError(c, err, "join channel")
		return
	}
	user, err := loadUser(ctx, h.deps.DB, me.ID)
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}
	member := models.GroupMemberDTO{User: publicUserDTO(user, uuid.Nil), Role: "member"}
	h.deps.Calls().addToGroupCalls(id, me.ID)
	if memberIDs, err := groupMemberIDs(ctx, h.deps.DB, id); err == nil {
		h.deps.Hub().SendToUsers(memberIDs, "group.member_added", gin.H{"group_id": id, "member": member})
	}
	dto, err := h.groupDTO(ctx, group, me.ID)
	if err != nil {
		h.deps.internalError(c, err, "load channel")
		return
	}
	c.JSON(http.StatusOK, gin.H{"group": dto})
}

// LeaveGroup removes the caller from a group or channel (POST /groups/:id/leave). The owner
// cannot leave.
func (h *GroupHandler) LeaveGroup(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	group, err := loadGroup(ctx, h.deps.DB, id)
	if err == nil {
		_, err = loadMembership(ctx, h.deps.DB, id, userID)
	}
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load group")
		return
	}
	if group.OwnerID == userID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the owner cannot leave; ask an admin to delete the group instead"})
		return
	}
	memberIDs, err := groupMemberIDs(ctx, h.deps.DB, id)
	if err != nil {
		h.deps.internalError(c, err, "load group members")
		return
	}
	if _, err := h.deps.DB.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, id, userID); err != nil {
		h.deps.internalError(c, err, "leave group")
		return
	}
	h.deps.Calls().removeFromGroupCalls(id, userID)
	h.deps.Hub().SendToUsers(memberIDs, "group.member_removed", gin.H{"group_id": id, "user_id": userID})
	c.JSON(http.StatusOK, gin.H{"left": true})
}

// requireRole checks the caller's membership against a role predicate, writing an error response
// and returning false if the check fails. Non-members get 404 so group existence is not revealed.
func (h *GroupHandler) requireRole(c *gin.Context, groupID, userID uuid.UUID,
	allowed func(*models.GroupMember) bool, denied string) bool {
	ctx := c.Request.Context()
	_, err := loadGroup(ctx, h.deps.DB, groupID)
	var member *models.GroupMember
	if err == nil {
		member, err = loadMembership(ctx, h.deps.DB, groupID, userID)
	}
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return false
	}
	if err != nil {
		h.deps.internalError(c, err, "check group membership")
		return false
	}
	if !allowed(member) {
		c.JSON(http.StatusForbidden, gin.H{"error": denied})
		return false
	}
	return true
}

// canModerate reports whether actor may act on target (remove them, or mute them in a call):
// admins can act on anyone but the group owner, moderators only on plain members, and nobody
// on themselves.
func canModerate(actor, target *models.GroupMember, ownerID uuid.UUID) bool {
	if actor.UserID == target.UserID || target.UserID == ownerID {
		return false
	}
	if actor.IsAdmin() {
		return true
	}
	return actor.CanRemoveMembers() && !target.IsModerator()
}

// moderationCheck loads the group and both memberships and checks canModerate, writing an error
// response and returning false if the action is not allowed.
func moderationCheck(c *gin.Context, deps *Dependencies, groupID, actorID, targetID uuid.UUID, denied string) bool {
	ctx := c.Request.Context()
	group, err := loadGroup(ctx, deps.DB, groupID)
	var actor, target *models.GroupMember
	if err == nil {
		actor, err = loadMembership(ctx, deps.DB, groupID, actorID)
	}
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return false
	}
	if err == nil {
		target, err = loadMembership(ctx, deps.DB, groupID, targetID)
	}
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "that person is not a member of this group"})
		return false
	}
	if err != nil {
		deps.internalError(c, err, "check group membership")
		return false
	}
	if !canModerate(actor, target, group.OwnerID) {
		c.JSON(http.StatusForbidden, gin.H{"error": denied})
		return false
	}
	return true
}

// RemoveMember removes someone from a group (see canModerate for who may). They lose access to
// the group straight away and are dropped from any call going on in it.
func (h *GroupHandler) RemoveMember(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	targetID, ok := uuidParam(c, "userId")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	if !moderationCheck(c, h.deps, id, userID, targetID, "you do not have permission to remove this member") {
		return
	}

	// Everyone who was in the group, including the removed person, hears about it.
	memberIDs, err := groupMemberIDs(ctx, h.deps.DB, id)
	if err != nil {
		h.deps.internalError(c, err, "load group members")
		return
	}
	if _, err := h.deps.DB.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, id, targetID); err != nil {
		h.deps.internalError(c, err, "remove member")
		return
	}
	h.deps.Calls().removeFromGroupCalls(id, targetID)

	h.deps.Hub().SendToUsers(memberIDs, "group.member_removed",
		gin.H{"group_id": id, "user_id": targetID, "removed_by": userID})
	h.deps.Kafka.Publish(ctx, "group.member_removed", id.String(),
		gin.H{"group_id": id, "user_id": targetID, "removed_by": userID})
	c.JSON(http.StatusOK, gin.H{"removed": true})
}
