package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

const messageColumns = `m.id, m.sender_id, m.receiver_id, m.group_id, m.content_encrypted, m.content_iv,
	m.content_tag, COALESCE(m.message_type, 'text'), m.file_id, COALESCE(m.is_edited, false), m.edited_at,
	COALESCE(m.is_deleted, false), m.deleted_at, m.read_at, m.created_at, m.updated_at,
	COALESCE(m.key_version, 1), m.parent_id`

// Viewer-specific columns ($1 = viewer) appended to messageColumns when listing messages:
// read_count, recipient_count, reply_count, unread_reply_count, last_reply_at, unread.
const groupMessageExtras = `
	(SELECT COUNT(*) FROM message_reads r WHERE r.message_id = m.id),
	(SELECT COUNT(*) FROM group_members gm
	 WHERE gm.group_id = m.group_id AND gm.user_id <> m.sender_id AND gm.joined_at <= m.created_at),
	(SELECT COUNT(*) FROM messages x WHERE x.parent_id = m.id AND NOT COALESCE(x.is_deleted, false)),
	(SELECT COUNT(*) FROM messages x
	 WHERE x.parent_id = m.id AND NOT COALESCE(x.is_deleted, false) AND x.sender_id <> $1
	   AND NOT EXISTS (SELECT 1 FROM message_reads r WHERE r.message_id = x.id AND r.user_id = $1)),
	(SELECT MAX(x.created_at) FROM messages x WHERE x.parent_id = m.id AND NOT COALESCE(x.is_deleted, false)),
	(m.sender_id <> $1
	 AND m.created_at >= COALESCE((SELECT joined_at FROM group_members WHERE group_id = m.group_id AND user_id = $1), m.created_at)
	 AND NOT EXISTS (SELECT 1 FROM message_reads r WHERE r.message_id = m.id AND r.user_id = $1))`

const directMessageExtras = `
	CASE WHEN m.read_at IS NULL THEN 0 ELSE 1 END, 1, 0, 0, NULL::timestamp,
	(m.receiver_id = $1 AND m.read_at IS NULL)`

// mentionPattern matches @username (usernames of letters, digits, '_', '.', '-').
var mentionPattern = regexp.MustCompile(`(?:^|[^\w@])@([A-Za-z0-9_.\-]{3,50})`)

// MessageHandler handles direct and group messages, threads and mentions. Message content is
// encrypted at rest with versioned AES-256-GCM data keys and delivered over WebSocket.
type MessageHandler struct {
	deps *Dependencies
}

// NewMessageHandler creates a MessageHandler.
func NewMessageHandler(deps *Dependencies) *MessageHandler {
	return &MessageHandler{deps: deps}
}

// messageScanDest returns scan destinations matching messageColumns.
func messageScanDest(m *models.Message) []interface{} {
	return []interface{}{
		&m.ID, &m.SenderID, &m.ReceiverID, &m.GroupID, &m.ContentEncrypted, &m.ContentIV,
		&m.ContentTag, &m.MessageType, &m.FileID, &m.IsEdited, &m.EditedAt,
		&m.IsDeleted, &m.DeletedAt, &m.ReadAt, &m.CreatedAt, &m.UpdatedAt,
		&m.KeyVersion, &m.ParentID,
	}
}

func scanMessage(row rowScanner, extra ...interface{}) (*models.Message, error) {
	var m models.Message
	if err := row.Scan(append(messageScanDest(&m), extra...)...); err != nil {
		return nil, err
	}
	return &m, nil
}

// directPair is a condition matching the direct messages between users a and b (SQL
// expressions) on table alias t, written to use the idx_messages_direct_history index.
func directPair(t, a, b string) string {
	return "LEAST(" + t + ".sender_id, " + t + ".receiver_id) = LEAST(" + a + ", " + b + ")" +
		" AND GREATEST(" + t + ".sender_id, " + t + ".receiver_id) = GREATEST(" + a + ", " + b + ")" +
		" AND " + t + ".receiver_id IS NOT NULL"
}

// decryptMessage returns a message's plaintext, or "" if its data key version is unavailable.
func decryptMessage(deps *Dependencies, msg *models.Message) string {
	content, err := deps.EncryptionService.DecryptField(msg.ContentEncrypted, msg.ContentIV, msg.ContentTag, msg.KeyVersion)
	if err != nil {
		deps.Logger.WithField("message_id", msg.ID).WithField("key_version", msg.KeyVersion).
			Warn("Failed to decrypt message")
		return ""
	}
	return string(content)
}

func (h *MessageHandler) decryptContent(msg *models.Message) string {
	return decryptMessage(h.deps, msg)
}

// queryMessages runs a listing query whose SELECT list is messageColumns, the viewer extras,
// the sender's userColumns("u") and COUNT(*) OVER (), and returns enriched DTOs.
func (h *MessageHandler) queryMessages(ctx context.Context, viewer uuid.UUID, query string, args ...interface{}) ([]models.MessageDTO, int, error) {
	rows, err := h.deps.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	messages := []models.MessageDTO{}
	total := 0
	for rows.Next() {
		var sender models.User
		var readCount, recipientCount, replyCount, unreadReplies int
		var lastReplyAt *time.Time
		var unread bool
		dest := []interface{}{&readCount, &recipientCount, &replyCount, &unreadReplies, &lastReplyAt, &unread}
		dest = append(append(dest, userScanDest(&sender)...), &total)
		msg, err := scanMessage(rows, dest...)
		if err != nil {
			return nil, 0, err
		}

		dto := msg.ToDTO(&sender)
		dto.Sender = publicUserDTO(&sender, viewer)
		dto.Content = h.decryptContent(msg)
		dto.ParentID = msg.ParentID
		dto.ReadCount, dto.RecipientCount = readCount, recipientCount
		dto.ReplyCount, dto.UnreadReplyCount, dto.LastReplyAt = replyCount, unreadReplies, lastReplyAt
		dto.Unread = unread
		messages = append(messages, *dto)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := enrichMessages(ctx, h.deps.DB, messages); err != nil {
		return nil, 0, err
	}
	return messages, total, nil
}

// enrichMessages loads attachment metadata and mentions for a page of messages in two queries.
func enrichMessages(ctx context.Context, db *sql.DB, messages []models.MessageDTO) error {
	if len(messages) == 0 {
		return nil
	}
	ids := make([]string, 0, len(messages))
	var fileIDs []string
	for _, m := range messages {
		ids = append(ids, m.ID.String())
		if m.FileID != nil {
			fileIDs = append(fileIDs, m.FileID.String())
		}
	}

	files := map[uuid.UUID]models.FileDTO{}
	if len(fileIDs) > 0 {
		rows, err := db.QueryContext(ctx,
			"SELECT "+fileColumns+" FROM files f WHERE f.id = ANY($1) AND f.deleted_at IS NULL", pq.Array(fileIDs))
		if err != nil {
			return err
		}
		for rows.Next() {
			f, err := scanFile(rows)
			if err != nil {
				rows.Close()
				return err
			}
			files[f.ID] = *f.ToDTO(nil)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}

	mentions := map[uuid.UUID][]models.MentionDTO{}
	rows, err := db.QueryContext(ctx, `
		SELECT mm.message_id, u.id, u.username
		FROM message_mentions mm JOIN users u ON u.id = mm.user_id
		WHERE mm.message_id = ANY($1)
		ORDER BY u.username`, pq.Array(ids))
	if err != nil {
		return err
	}
	for rows.Next() {
		var messageID uuid.UUID
		var mention models.MentionDTO
		if err := rows.Scan(&messageID, &mention.UserID, &mention.Username); err != nil {
			rows.Close()
			return err
		}
		mentions[messageID] = append(mentions[messageID], mention)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range messages {
		if messages[i].FileID != nil {
			if f, ok := files[*messages[i].FileID]; ok {
				messages[i].Attachments = []models.FileDTO{f}
			}
		}
		messages[i].Mentions = mentions[messages[i].ID]
	}
	return nil
}

// resolveMentions finds the @usernames in content that belong to people in the conversation
// (group members, or the other participant of a direct message), excluding the sender.
func resolveMentions(ctx context.Context, tx *sql.Tx, content string, sender uuid.UUID, groupID, receiverID *uuid.UUID) ([]models.MentionDTO, error) {
	seen := map[string]bool{}
	var names []string
	for _, match := range mentionPattern.FindAllStringSubmatch(content, -1) {
		name := strings.ToLower(strings.TrimRight(match[1], ".-"))
		if len(name) >= 3 && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}

	var rows *sql.Rows
	var err error
	if groupID != nil {
		rows, err = tx.QueryContext(ctx, `
			SELECT u.id, u.username FROM users u
			JOIN group_members gm ON gm.user_id = u.id AND gm.group_id = $1
			WHERE lower(u.username) = ANY($2) AND u.id <> $3 AND u.deleted_at IS NULL`,
			*groupID, pq.Array(names), sender)
	} else {
		rows, err = tx.QueryContext(ctx, `
			SELECT u.id, u.username FROM users u
			WHERE u.id = $1 AND lower(u.username) = ANY($2)`, *receiverID, pq.Array(names))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mentions []models.MentionDTO
	for rows.Next() {
		var m models.MentionDTO
		if err := rows.Scan(&m.UserID, &m.Username); err != nil {
			return nil, err
		}
		mentions = append(mentions, m)
	}
	return mentions, rows.Err()
}

func saveMentions(ctx context.Context, tx *sql.Tx, messageID uuid.UUID, mentions []models.MentionDTO) error {
	for _, m := range mentions {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO message_mentions (message_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			messageID, m.UserID); err != nil {
			return err
		}
	}
	return nil
}

// SendMessage sends a message to a user (receiver_id) or a group (group_id). With parent_id it
// is a reply in that group message's thread. With file_id, content is an optional note on the
// attachment. @username mentions of people in the conversation are recorded.
func (h *MessageHandler) SendMessage(c *gin.Context) {
	var req models.SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if (req.ReceiverID == nil) == (req.GroupID == nil) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exactly one of receiver_id or group_id is required"})
		return
	}
	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" && req.FileID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is required"})
		return
	}
	if req.ParentID != nil && req.GroupID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "threads are only available in groups"})
		return
	}

	ctx := c.Request.Context()
	sender, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	senderID := sender.ID

	var recipients []uuid.UUID
	var conversationID *uuid.UUID

	if req.ReceiverID != nil {
		if *req.ReceiverID == senderID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot message yourself"})
			return
		}
		// Only people in the same company can message each other.
		receiver, err := loadColleague(ctx, h.deps.DB, sender.CompanyID, *req.ReceiverID)
		if errors.Is(err, errNotFound) || (err == nil && !receiver.IsActive()) {
			c.JSON(http.StatusNotFound, gin.H{"error": "receiver not found"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "load receiver")
			return
		}
		id, err := h.ensureConversation(ctx, senderID, receiver.ID)
		if err != nil {
			h.deps.internalError(c, err, "create conversation")
			return
		}
		conversationID = &id
		recipients = []uuid.UUID{senderID, receiver.ID}
	} else {
		_, err := loadGroup(ctx, h.deps.DB, *req.GroupID)
		if err == nil {
			_, err = loadMembership(ctx, h.deps.DB, *req.GroupID, senderID)
		}
		if errors.Is(err, errNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "check group membership")
			return
		}
		if recipients, err = groupMemberIDs(ctx, h.deps.DB, *req.GroupID); err != nil {
			h.deps.internalError(c, err, "load group members")
			return
		}
	}

	if req.ParentID != nil {
		parent, err := scanMessage(h.deps.DB.QueryRowContext(ctx,
			"SELECT "+messageColumns+" FROM messages m WHERE m.id = $1", *req.ParentID))
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (parent.IsDeleted || parent.GroupID == nil || *parent.GroupID != *req.GroupID)) {
			c.JSON(http.StatusNotFound, gin.H{"error": "thread not found"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "load thread parent")
			return
		}
		if parent.ParentID != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "replies cannot have their own threads"})
			return
		}
	}

	if req.FileID != nil {
		var exists bool
		err := h.deps.DB.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM files WHERE id = $1 AND uploaded_by = $2 AND deleted_at IS NULL)`,
			*req.FileID, senderID).Scan(&exists)
		if err != nil {
			h.deps.internalError(c, err, "check file")
			return
		}
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file_id must refer to a file you uploaded"})
			return
		}
	}

	ciphertext, iv, tag, keyVersion, err := h.deps.EncryptionService.EncryptField([]byte(req.Content))
	if err != nil {
		h.deps.internalError(c, err, "encrypt message")
		return
	}

	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()

	msg, err := scanMessage(tx.QueryRowContext(ctx, `
		INSERT INTO messages AS m (sender_id, receiver_id, group_id, content_encrypted, content_iv, content_tag,
			message_type, file_id, key_version, parent_id, client_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (sender_id, client_id) WHERE client_id IS NOT NULL DO NOTHING
		RETURNING `+messageColumns,
		senderID, req.ReceiverID, req.GroupID, ciphertext, iv, tag, req.MessageType, req.FileID, keyVersion, req.ParentID,
		req.ClientID,
	))
	if errors.Is(err, sql.ErrNoRows) && req.ClientID != nil {
		// A retry of a send that already succeeded: return the original message.
		tx.Rollback()
		h.replyWithExisting(c, senderID, *req.ClientID, conversationID)
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "insert message")
		return
	}
	if req.FileID != nil {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO message_attachments (message_id, file_id) VALUES ($1, $2)`, msg.ID, *req.FileID,
		); err != nil {
			h.deps.internalError(c, err, "attach file")
			return
		}
	}
	mentions, err := resolveMentions(ctx, tx, req.Content, senderID, req.GroupID, req.ReceiverID)
	if err == nil {
		err = saveMentions(ctx, tx, msg.ID, mentions)
	}
	if err != nil {
		h.deps.internalError(c, err, "save mentions")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "commit message")
		return
	}

	// The message is committed: from here on, failures only make the response less complete.
	// Returning an error would make the client retry and send the message twice.
	dto := msg.ToDTO(nil)
	if sender, err := loadUser(ctx, h.deps.DB, senderID); err == nil {
		dto.Sender = publicUserDTO(sender, uuid.Nil)
	} else {
		h.deps.Logger.WithError(err).Warn("Failed to load sender of a sent message")
	}
	dto.Content = req.Content
	dto.ParentID = msg.ParentID
	dto.RecipientCount = len(recipients) - 1 // recipients includes the sender
	dtos := []models.MessageDTO{*dto}
	if err := enrichMessages(ctx, h.deps.DB, dtos); err == nil {
		*dto = dtos[0]
	} else {
		h.deps.Logger.WithError(err).Warn("Failed to load details of a sent message")
	}

	h.deps.Hub().SendToUsers(recipients, "message.new", dto)
	h.deps.Kafka.Publish(ctx, "message.sent", msg.ID.String(), gin.H{
		"message_id":   msg.ID,
		"sender_id":    senderID,
		"receiver_id":  msg.ReceiverID,
		"group_id":     msg.GroupID,
		"parent_id":    msg.ParentID,
		"message_type": msg.MessageType,
		"mentions":     len(mentions),
	})

	resp := gin.H{"message": dto}
	if conversationID != nil {
		resp["conversation_id"] = conversationID
	}
	c.JSON(http.StatusCreated, resp)
}

// replyWithExisting responds with the message the sender already sent with this client_id.
func (h *MessageHandler) replyWithExisting(c *gin.Context, senderID, clientID uuid.UUID, conversationID *uuid.UUID) {
	ctx := c.Request.Context()
	msg, err := scanMessage(h.deps.DB.QueryRowContext(ctx,
		"SELECT "+messageColumns+" FROM messages m WHERE m.sender_id = $1 AND m.client_id = $2", senderID, clientID))
	if err != nil {
		h.deps.internalError(c, err, "load existing message")
		return
	}
	dto := msg.ToDTO(nil)
	if sender, err := loadUser(ctx, h.deps.DB, senderID); err == nil {
		dto.Sender = publicUserDTO(sender, senderID)
	}
	dto.Content = h.decryptContent(msg)
	dto.ParentID = msg.ParentID
	dtos := []models.MessageDTO{*dto}
	if err := enrichMessages(ctx, h.deps.DB, dtos); err == nil {
		*dto = dtos[0]
	}
	resp := gin.H{"message": dto, "duplicate": true}
	if conversationID != nil {
		resp["conversation_id"] = conversationID
	}
	c.JSON(http.StatusOK, resp)
}

// ensureConversation returns the conversation between two users, creating it if needed.
// Participants are stored in a canonical order so each pair has a single row.
func (h *MessageHandler) ensureConversation(ctx context.Context, a, b uuid.UUID) (uuid.UUID, error) {
	if a.String() > b.String() {
		a, b = b, a
	}
	var id uuid.UUID
	err := h.deps.DB.QueryRowContext(ctx, `
		INSERT INTO conversations (user_id_1, user_id_2) VALUES ($1, $2)
		ON CONFLICT (user_id_1, user_id_2) DO UPDATE SET user_id_1 = EXCLUDED.user_id_1
		RETURNING id`, a, b).Scan(&id)
	return id, err
}

// GetMessages lists messages newest first. :id may be a conversation ID, a group ID,
// or the other user's ID for a direct conversation. Group listings contain top-level messages
// only (thread replies are fetched with GetThread). Each message is flagged "unread" if the
// caller had not read it yet. Fetching has no side effects: clients acknowledge what they
// displayed with POST /messages/:id/read.
func (h *MessageHandler) GetMessages(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	limit, offset := paging(c)

	otherUser, groupID, err := h.resolveConversation(ctx, id, userID)
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "conversation not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "resolve conversation")
		return
	}

	var messages []models.MessageDTO
	var total int
	if groupID != uuid.Nil {
		messages, total, err = h.queryMessages(ctx, userID, `
			SELECT `+messageColumns+`, `+groupMessageExtras+`, `+userColumns("u")+`, COUNT(*) OVER ()
			FROM messages m JOIN users u ON u.id = m.sender_id
			WHERE m.group_id = $2 AND m.parent_id IS NULL AND NOT COALESCE(m.is_deleted, false)
			ORDER BY m.created_at DESC
			LIMIT $3 OFFSET $4`, userID, groupID, limit, offset)
	} else {
		messages, total, err = h.queryMessages(ctx, userID, `
			SELECT `+messageColumns+`, `+directMessageExtras+`, `+userColumns("u")+`, COUNT(*) OVER ()
			FROM messages m JOIN users u ON u.id = m.sender_id
			WHERE `+directPair("m", "$1", "$2")+` AND NOT COALESCE(m.is_deleted, false)
			ORDER BY m.created_at DESC
			LIMIT $3 OFFSET $4`, userID, otherUser, limit, offset)
	}
	if err != nil {
		h.deps.internalError(c, err, "load messages")
		return
	}

	c.JSON(http.StatusOK, models.MessageListResponse{Messages: messages, Total: total, Limit: limit, Offset: offset})
}

// GetThread returns a group message and its replies (oldest first). Clients acknowledge the
// replies they displayed with POST /messages/:id/thread/read.
func (h *MessageHandler) GetThread(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	limit, offset := paging(c)
	if c.Query("limit") == "" {
		limit = maxPageSize
	}

	var groupID *uuid.UUID
	var parentOf *uuid.UUID
	err := h.deps.DB.QueryRowContext(ctx,
		`SELECT group_id, parent_id FROM messages WHERE id = $1 AND NOT COALESCE(is_deleted, false)`, id,
	).Scan(&groupID, &parentOf)
	if err == nil && groupID != nil {
		_, err = loadMembership(ctx, h.deps.DB, *groupID, userID)
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errNotFound) || (err == nil && groupID == nil) {
		c.JSON(http.StatusNotFound, gin.H{"error": "thread not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load thread")
		return
	}
	if parentOf != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this message is a reply; open its parent's thread"})
		return
	}

	parents, _, err := h.queryMessages(ctx, userID, `
		SELECT `+messageColumns+`, `+groupMessageExtras+`, `+userColumns("u")+`, COUNT(*) OVER ()
		FROM messages m JOIN users u ON u.id = m.sender_id
		WHERE m.id = $2`, userID, id)
	if err != nil || len(parents) == 0 {
		h.deps.internalError(c, err, "load thread parent")
		return
	}
	replies, total, err := h.queryMessages(ctx, userID, `
		SELECT `+messageColumns+`, `+groupMessageExtras+`, `+userColumns("u")+`, COUNT(*) OVER ()
		FROM messages m JOIN users u ON u.id = m.sender_id
		WHERE m.parent_id = $2 AND NOT COALESCE(m.is_deleted, false)
		ORDER BY m.created_at
		LIMIT $3 OFFSET $4`, userID, id, limit, offset)
	if err != nil {
		h.deps.internalError(c, err, "load thread replies")
		return
	}

	c.JSON(http.StatusOK, gin.H{"parent": parents[0], "replies": replies, "total": total, "limit": limit, "offset": offset})
}

// EditMessage changes a message's text, or the note on an attachment. Senders can edit text
// messages within 15 minutes and attachment notes at any time.
func (h *MessageHandler) EditMessage(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req models.EditMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	req.Content = strings.TrimSpace(req.Content)

	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	msg, err := scanMessage(h.deps.DB.QueryRowContext(ctx, "SELECT "+messageColumns+" FROM messages m WHERE m.id = $1", id))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && msg.IsDeleted) {
		c.JSON(http.StatusNotFound, gin.H{"error": "message not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load message")
		return
	}
	if msg.SenderID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only edit your own messages"})
		return
	}
	hasAttachment := msg.FileID != nil
	if !hasAttachment && req.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is required"})
		return
	}
	if !hasAttachment && !msg.CanEdit(userID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "messages can only be edited within 15 minutes of sending"})
		return
	}

	ciphertext, iv, tag, keyVersion, err := h.deps.EncryptionService.EncryptField([]byte(req.Content))
	if err != nil {
		h.deps.internalError(c, err, "encrypt message")
		return
	}

	tx, err := h.deps.DB.BeginTx(ctx, nil)
	if err != nil {
		h.deps.internalError(c, err, "begin transaction")
		return
	}
	defer tx.Rollback()

	updated, err := scanMessage(tx.QueryRowContext(ctx, `
		UPDATE messages AS m SET content_encrypted = $2, content_iv = $3, content_tag = $4, key_version = $5,
			is_edited = true, edited_at = NOW()
		WHERE m.id = $1
		RETURNING `+messageColumns, id, ciphertext, iv, tag, keyVersion))
	if err != nil {
		h.deps.internalError(c, err, "update message")
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM message_mentions WHERE message_id = $1`, id); err != nil {
		h.deps.internalError(c, err, "update mentions")
		return
	}
	mentions, err := resolveMentions(ctx, tx, req.Content, userID, msg.GroupID, msg.ReceiverID)
	if err == nil {
		err = saveMentions(ctx, tx, id, mentions)
	}
	if err != nil {
		h.deps.internalError(c, err, "save mentions")
		return
	}
	if err := tx.Commit(); err != nil {
		h.deps.internalError(c, err, "commit edit")
		return
	}

	dto := updated.ToDTO(nil)
	dto.Content = req.Content
	dto.ParentID = updated.ParentID
	dtos := []models.MessageDTO{*dto}
	if err := enrichMessages(ctx, h.deps.DB, dtos); err == nil {
		*dto = dtos[0]
	}

	recipients := []uuid.UUID{msg.SenderID}
	if msg.GroupID != nil {
		recipients, _ = groupMemberIDs(ctx, h.deps.DB, *msg.GroupID)
	} else if msg.ReceiverID != nil {
		recipients = append(recipients, *msg.ReceiverID)
	}
	h.deps.Hub().SendToUsers(recipients, "message.updated", dto)
	h.deps.Kafka.Publish(ctx, "message.edited", id.String(), gin.H{"message_id": id, "edited_by": userID})
	c.JSON(http.StatusOK, gin.H{"message": dto})
}

// readBatchSize bounds how many messages one statement marks read.
const readBatchSize = 1000

// MarkRead handles POST /messages/:id/read {"up_to": <message id>}: the caller has seen the
// messages in the conversation (:id as in GetMessages) up to and including up_to. Senders get a
// live read receipt. Only top-level messages are covered in groups; see MarkThreadRead.
func (h *MessageHandler) MarkRead(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req models.MarkReadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	otherUser, groupID, err := h.resolveConversation(ctx, id, userID)
	if errors.Is(err, errNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "conversation not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "resolve conversation")
		return
	}

	upTo, err := scanMessage(h.deps.DB.QueryRowContext(ctx, "SELECT "+messageColumns+" FROM messages m WHERE m.id = $1", req.UpTo))
	inConversation := err == nil && upTo.ParentID == nil &&
		((groupID != uuid.Nil && upTo.GroupID != nil && *upTo.GroupID == groupID) ||
			(groupID == uuid.Nil && upTo.ReceiverID != nil &&
				((upTo.SenderID == userID && *upTo.ReceiverID == otherUser) || (upTo.SenderID == otherUser && *upTo.ReceiverID == userID))))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !inConversation) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "up_to must be a message in this conversation"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load message")
		return
	}

	var marked int
	if groupID == uuid.Nil {
		marked, err = h.markRead(ctx, userID, otherUser, upTo.CreatedAt)
	} else {
		marked, err = h.markGroupRead(ctx, userID, groupID, nil, upTo.CreatedAt)
	}
	if err != nil {
		h.deps.internalError(c, err, "mark messages read")
		return
	}
	c.JSON(http.StatusOK, gin.H{"marked": marked})
}

// MarkThreadRead handles POST /messages/:id/thread/read {"up_to": <reply id>}: the caller has
// seen the replies in the thread of message :id up to and including up_to.
func (h *MessageHandler) MarkThreadRead(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	var req models.MarkReadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)

	var groupID *uuid.UUID
	err := h.deps.DB.QueryRowContext(ctx,
		`SELECT group_id FROM messages WHERE id = $1 AND parent_id IS NULL AND NOT COALESCE(is_deleted, false)`, id,
	).Scan(&groupID)
	if err == nil && groupID != nil {
		_, err = loadMembership(ctx, h.deps.DB, *groupID, userID)
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errNotFound) || (err == nil && groupID == nil) {
		c.JSON(http.StatusNotFound, gin.H{"error": "thread not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load thread")
		return
	}

	var cutoff time.Time
	err = h.deps.DB.QueryRowContext(ctx,
		`SELECT created_at FROM messages WHERE id = $1 AND parent_id = $2`, req.UpTo, id).Scan(&cutoff)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "up_to must be a reply in this thread"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load reply")
		return
	}
	marked, err := h.markGroupRead(ctx, userID, *groupID, &id, cutoff)
	if err != nil {
		h.deps.internalError(c, err, "mark replies read")
		return
	}
	c.JSON(http.StatusOK, gin.H{"marked": marked})
}

// markRead marks the reader's unread direct messages from sender, sent up to cutoff, as read
// and notifies both users over WebSocket ("messages.read"), so the sender's read receipts update
// live. It works in bounded batches.
func (h *MessageHandler) markRead(ctx context.Context, reader, sender uuid.UUID, cutoff time.Time) (int, error) {
	total := 0
	for {
		ids, readAt, err := h.markReadBatch(ctx, reader, sender, cutoff)
		if err != nil {
			return total, err
		}
		if len(ids) > 0 {
			h.deps.Hub().SendToUsers([]uuid.UUID{sender, reader}, "messages.read", gin.H{
				"reader_id":   reader,
				"sender_id":   sender,
				"message_ids": ids,
				"read_at":     readAt,
			})
		}
		total += len(ids)
		if len(ids) < readBatchSize {
			return total, nil
		}
	}
}

func (h *MessageHandler) markReadBatch(ctx context.Context, reader, sender uuid.UUID, cutoff time.Time) ([]uuid.UUID, time.Time, error) {
	var readAt time.Time
	rows, err := h.deps.DB.QueryContext(ctx, `
		UPDATE messages SET read_at = NOW()
		WHERE id IN (
			SELECT id FROM messages
			WHERE receiver_id = $1 AND sender_id = $2 AND read_at IS NULL AND NOT COALESCE(is_deleted, false)
			  AND created_at <= $3
			ORDER BY created_at
			LIMIT $4)
		RETURNING id, read_at`, reader, sender, cutoff, readBatchSize)
	if err != nil {
		return nil, readAt, err
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id, &readAt); err != nil {
			return nil, readAt, err
		}
		ids = append(ids, id)
	}
	return ids, readAt, rows.Err()
}

// markGroupRead records that reader has read the group's top-level messages (parentID nil) or
// the replies in one thread, sent up to cutoff, and notifies each affected sender so their
// receipts update live. It works in bounded batches.
func (h *MessageHandler) markGroupRead(ctx context.Context, reader, groupID uuid.UUID, parentID *uuid.UUID, cutoff time.Time) (int, error) {
	total := 0
	for {
		n, err := h.markGroupReadBatch(ctx, reader, groupID, parentID, cutoff)
		if err != nil {
			return total, err
		}
		total += n
		if n < readBatchSize {
			return total, nil
		}
	}
}

func (h *MessageHandler) markGroupReadBatch(ctx context.Context, reader, groupID uuid.UUID, parentID *uuid.UUID, cutoff time.Time) (int, error) {
	scope := "m.parent_id IS NULL"
	args := []interface{}{groupID, reader, cutoff, readBatchSize}
	if parentID != nil {
		scope = "m.parent_id = $5"
		args = append(args, *parentID)
	}
	rows, err := h.deps.DB.QueryContext(ctx, `
		WITH inserted AS (
			INSERT INTO message_reads (message_id, user_id)
			SELECT m.id, $2 FROM messages m
			WHERE m.group_id = $1 AND `+scope+` AND m.sender_id <> $2 AND NOT COALESCE(m.is_deleted, false)
			  AND m.created_at <= $3
			  AND NOT EXISTS (SELECT 1 FROM message_reads r WHERE r.message_id = m.id AND r.user_id = $2)
			ORDER BY m.created_at
			LIMIT $4
			ON CONFLICT (message_id, user_id) DO NOTHING
			RETURNING message_id, read_at
		)
		SELECT i.message_id, i.read_at, m.sender_id
		FROM inserted i JOIN messages m ON m.id = i.message_id`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	bySender := map[uuid.UUID][]uuid.UUID{}
	var all []uuid.UUID
	var readAt time.Time
	for rows.Next() {
		var messageID, senderID uuid.UUID
		if err := rows.Scan(&messageID, &readAt, &senderID); err != nil {
			return 0, err
		}
		bySender[senderID] = append(bySender[senderID], messageID)
		all = append(all, messageID)
	}
	if err := rows.Err(); err != nil || len(all) == 0 {
		return 0, err
	}

	for senderID, ids := range bySender {
		h.deps.Hub().SendToUsers([]uuid.UUID{senderID}, "messages.read", gin.H{
			"reader_id": reader, "group_id": groupID, "parent_id": parentID, "message_ids": ids, "read_at": readAt,
		})
	}
	// The reader's other tabs/devices clear their unread markers.
	h.deps.Hub().SendToUsers([]uuid.UUID{reader}, "messages.read", gin.H{
		"reader_id": reader, "group_id": groupID, "parent_id": parentID, "message_ids": all, "read_at": readAt,
	})
	return len(all), nil
}

// messageReader is one recipient's read status, as listed by GetMessageReads.
type messageReader struct {
	User   *models.UserDTO `json:"user"`
	ReadAt *time.Time      `json:"read_at"`
}

// GetMessageReads lists who has and has not read a message. Only the sender can see it.
// For group messages, recipients are the members who belonged to the group when it was sent
// (plus anyone who joined later and has read it).
func (h *MessageHandler) GetMessageReads(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)

	msg, err := scanMessage(h.deps.DB.QueryRowContext(ctx,
		"SELECT "+messageColumns+" FROM messages m WHERE m.id = $1 AND NOT COALESCE(m.is_deleted, false)", id))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "message not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load message")
		return
	}
	if msg.SenderID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "only the sender can see who read a message"})
		return
	}

	var rows *sql.Rows
	if msg.GroupID != nil {
		rows, err = h.deps.DB.QueryContext(ctx, `
			SELECT `+userColumns("u")+`, r.read_at
			FROM group_members gm
			JOIN users u ON u.id = gm.user_id
			LEFT JOIN message_reads r ON r.message_id = $1 AND r.user_id = gm.user_id
			WHERE gm.group_id = $2 AND gm.user_id <> $3
			  AND (gm.joined_at <= (SELECT created_at FROM messages WHERE id = $1) OR r.read_at IS NOT NULL)
			ORDER BY r.read_at NULLS LAST, u.username`, msg.ID, *msg.GroupID, msg.SenderID)
	} else {
		rows, err = h.deps.DB.QueryContext(ctx, `
			SELECT `+userColumns("u")+`, m.read_at
			FROM messages m JOIN users u ON u.id = m.receiver_id
			WHERE m.id = $1`, msg.ID)
	}
	if err != nil {
		h.deps.internalError(c, err, "load message reads")
		return
	}
	defer rows.Close()

	readBy := []messageReader{}
	notReadBy := []messageReader{}
	for rows.Next() {
		var readAt *time.Time
		user, err := scanUser(rows, &readAt)
		if err != nil {
			h.deps.internalError(c, err, "scan message read")
			return
		}
		entry := messageReader{User: publicUserDTO(user, userID), ReadAt: readAt}
		if readAt != nil {
			readBy = append(readBy, entry)
		} else {
			notReadBy = append(notReadBy, entry)
		}
	}
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "load message reads")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message_id":      msg.ID,
		"read_by":         readBy,
		"not_read_by":     notReadBy,
		"recipient_count": len(readBy) + len(notReadBy),
	})
}

// ListConversations returns the caller's direct conversations with the other participant,
// the latest message, and unread and unread-mention counts, most recently active first.
func (h *MessageHandler) ListConversations(c *gin.Context) {
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)
	limit, offset := paging(c)

	rows, err := h.deps.DB.QueryContext(ctx, `
		SELECT `+userColumns("u")+`, c.id, c.created_at,
			(SELECT COUNT(*) FROM messages m
			 WHERE m.receiver_id = $1 AND m.sender_id = u.id
			   AND m.read_at IS NULL AND NOT COALESCE(m.is_deleted, false)),
			(SELECT COUNT(*) FROM messages m
			 JOIN message_mentions mm ON mm.message_id = m.id AND mm.user_id = $1
			 WHERE m.receiver_id = $1 AND m.sender_id = u.id
			   AND m.read_at IS NULL AND NOT COALESCE(m.is_deleted, false)),
			COUNT(*) OVER ()
		FROM conversations c
		JOIN users u ON u.id = CASE WHEN c.user_id_1 = $1 THEN c.user_id_2 ELSE c.user_id_1 END
		WHERE c.user_id_1 = $1 OR c.user_id_2 = $1
		ORDER BY COALESCE(
			(SELECT MAX(m.created_at) FROM messages m
			 WHERE `+directPair("m", "c.user_id_1", "c.user_id_2")+`),
			c.created_at) DESC
		LIMIT $2 OFFSET $3`, userID, limit, offset)
	if err != nil {
		h.deps.internalError(c, err, "list conversations")
		return
	}

	conversations := []models.ConversationDTO{}
	total := 0
	for rows.Next() {
		var conv models.ConversationDTO
		other, err := scanUser(rows, &conv.ID, &conv.CreatedAt, &conv.UnreadCount, &conv.MentionCount, &total)
		if err != nil {
			rows.Close()
			h.deps.internalError(c, err, "scan conversation")
			return
		}
		conv.OtherUser = publicUserDTO(other, userID)
		conversations = append(conversations, conv)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		h.deps.internalError(c, err, "list conversations")
		return
	}

	// Latest message of every listed conversation, in one query.
	others := make([]string, len(conversations))
	index := make(map[uuid.UUID]int, len(conversations))
	for i := range conversations {
		others[i] = conversations[i].OtherUser.ID.String()
		index[conversations[i].OtherUser.ID] = i
	}
	if len(others) > 0 {
		rows, err := h.deps.DB.QueryContext(ctx, `
			SELECT o.id, `+messageColumns+`
			FROM unnest($2::uuid[]) AS o(id)
			CROSS JOIN LATERAL (
				SELECT x.* FROM messages x
				WHERE `+directPair("x", "$1::uuid", "o.id")+` AND NOT COALESCE(x.is_deleted, false)
				ORDER BY x.created_at DESC LIMIT 1) m`, userID, pq.Array(others))
		if err != nil {
			h.deps.internalError(c, err, "load last messages")
			return
		}
		var lastMessages []models.MessageDTO
		var owners []int
		for rows.Next() {
			var other uuid.UUID
			var msg models.Message
			dest := append([]interface{}{&other}, messageScanDest(&msg)...)
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				h.deps.internalError(c, err, "load last messages")
				return
			}
			dto := msg.ToDTO(nil)
			dto.Content = h.decryptContent(&msg)
			lastMessages = append(lastMessages, *dto)
			owners = append(owners, index[other])
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			h.deps.internalError(c, err, "load last messages")
			return
		}
		if err := enrichMessages(ctx, h.deps.DB, lastMessages); err != nil {
			h.deps.internalError(c, err, "load last messages")
			return
		}
		for j, i := range owners {
			last := lastMessages[j]
			conversations[i].LastMessage = &last
		}
	}

	c.JSON(http.StatusOK, gin.H{"conversations": conversations, "total": total, "limit": limit, "offset": offset})
}

// resolveConversation interprets id as a conversation, group or user the caller can see,
// returning either the other participant of a direct conversation or the group ID.
func (h *MessageHandler) resolveConversation(ctx context.Context, id, userID uuid.UUID) (otherUser, groupID uuid.UUID, err error) {
	var user1, user2 uuid.UUID
	err = h.deps.DB.QueryRowContext(ctx,
		`SELECT user_id_1, user_id_2 FROM conversations WHERE id = $1`, id).Scan(&user1, &user2)
	switch {
	case err == nil && user1 == userID:
		return user2, uuid.Nil, nil
	case err == nil && user2 == userID:
		return user1, uuid.Nil, nil
	case err == nil:
		return uuid.Nil, uuid.Nil, errNotFound
	case !errors.Is(err, sql.ErrNoRows):
		return uuid.Nil, uuid.Nil, err
	}

	if _, err = loadGroup(ctx, h.deps.DB, id); err == nil {
		if _, err = loadMembership(ctx, h.deps.DB, id, userID); err != nil {
			return uuid.Nil, uuid.Nil, err
		}
		return uuid.Nil, id, nil
	} else if !errors.Is(err, errNotFound) {
		return uuid.Nil, uuid.Nil, err
	}

	if id == userID {
		return uuid.Nil, uuid.Nil, errNotFound
	}
	me, err := loadUser(ctx, h.deps.DB, userID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if _, err = loadColleague(ctx, h.deps.DB, me.CompanyID, id); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return id, uuid.Nil, nil
}

// DeleteMessage soft-deletes a message. Senders can delete their own messages, and group
// moderators can delete any message in their group.
func (h *MessageHandler) DeleteMessage(c *gin.Context) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := middleware.GetUserID(c)

	msg, err := scanMessage(h.deps.DB.QueryRowContext(ctx, "SELECT "+messageColumns+" FROM messages m WHERE m.id = $1", id))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "message not found"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "load message")
		return
	}

	var recipients []uuid.UUID
	allowed := msg.CanDelete(userID)
	if msg.GroupID != nil {
		member, err := loadMembership(ctx, h.deps.DB, *msg.GroupID, userID)
		if err != nil && !errors.Is(err, errNotFound) {
			h.deps.internalError(c, err, "check group membership")
			return
		}
		if member == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "message not found"})
			return
		}
		allowed = allowed || (!msg.IsDeleted && member.CanDeleteMessages())
		recipients, _ = groupMemberIDs(ctx, h.deps.DB, *msg.GroupID)
	} else {
		if msg.SenderID != userID && (msg.ReceiverID == nil || *msg.ReceiverID != userID) {
			c.JSON(http.StatusNotFound, gin.H{"error": "message not found"})
			return
		}
		recipients = []uuid.UUID{msg.SenderID}
		if msg.ReceiverID != nil {
			recipients = append(recipients, *msg.ReceiverID)
		}
	}

	if msg.IsDeleted {
		c.JSON(http.StatusNotFound, gin.H{"error": "message not found"})
		return
	}
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "you cannot delete this message"})
		return
	}

	if _, err := h.deps.DB.ExecContext(ctx,
		`UPDATE messages SET is_deleted = true, deleted_at = NOW() WHERE id = $1`, id,
	); err != nil {
		h.deps.internalError(c, err, "delete message")
		return
	}

	h.deps.Hub().SendToUsers(recipients, "message.deleted", gin.H{"id": id, "group_id": msg.GroupID, "parent_id": msg.ParentID})
	h.deps.Kafka.Publish(ctx, "message.deleted", id.String(), gin.H{"message_id": id, "deleted_by": userID})
	c.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
}
