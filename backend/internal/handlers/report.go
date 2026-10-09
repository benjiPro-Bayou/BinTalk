package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var reportReasons = map[string]bool{"spam": true, "harassment": true, "inappropriate": true, "other": true}

// ReportHandler lets users report abusive messages or users to the admins.
type ReportHandler struct {
	deps *Dependencies
}

// NewReportHandler creates a ReportHandler.
func NewReportHandler(deps *Dependencies) *ReportHandler {
	return &ReportHandler{deps: deps}
}

// CreateReport files an abuse report about a message (message_id) or a user (user_id).
// Reporters can only report messages they can see, and not their own.
func (h *ReportHandler) CreateReport(c *gin.Context) {
	var req struct {
		MessageID *uuid.UUID `json:"message_id"`
		UserID    *uuid.UUID `json:"user_id"`
		Reason    string     `json:"reason" binding:"required"`
		Details   string     `json:"details" binding:"max=2000"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if !reportReasons[req.Reason] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason must be spam, harassment, inappropriate or other"})
		return
	}
	if (req.MessageID == nil) == (req.UserID == nil) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exactly one of message_id or user_id is required"})
		return
	}

	ctx := c.Request.Context()
	me, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	reporter := me.ID
	reportedUser := req.UserID
	var groupID *uuid.UUID

	if req.MessageID != nil {
		msg, err := scanMessage(h.deps.DB.QueryRowContext(ctx,
			"SELECT "+messageColumns+" FROM messages m WHERE m.id = $1", *req.MessageID))
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !canSeeMessage(ctx, h.deps.DB, reporter, msg.SenderID, msg.ReceiverID, msg.GroupID)) {
			c.JSON(http.StatusNotFound, gin.H{"error": "message not found"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "load reported message")
			return
		}
		if msg.SenderID == reporter {
			c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot report your own message"})
			return
		}
		reportedUser, groupID = &msg.SenderID, msg.GroupID
	} else {
		if *req.UserID == reporter {
			c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot report yourself"})
			return
		}
		if _, err := loadColleague(ctx, h.deps.DB, me.CompanyID, *req.UserID); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
	}

	var id uuid.UUID
	err := h.deps.DB.QueryRowContext(ctx, `
		INSERT INTO abuse_reports (reporter_id, reported_user_id, message_id, group_id, reason, details)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))
		RETURNING id`, reporter, reportedUser, req.MessageID, groupID, req.Reason, strings.TrimSpace(req.Details),
	).Scan(&id)
	if isUniqueViolation(err) {
		c.JSON(http.StatusConflict, gin.H{"error": "you have already reported this message"})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "create report")
		return
	}

	if admins, err := companyAdminIDs(ctx, h.deps.DB, me.CompanyID); err == nil {
		h.deps.Hub().SendToUsers(admins, "report.new", gin.H{"id": id, "reason": req.Reason})
	}
	h.deps.Kafka.Publish(ctx, "report.created", id.String(), gin.H{"report_id": id, "reason": req.Reason})
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "open"})
}

// canSeeMessage reports whether user is a participant of the message's conversation.
func canSeeMessage(ctx context.Context, db *sql.DB, user, sender uuid.UUID, receiver, group *uuid.UUID) bool {
	if user == sender || (receiver != nil && *receiver == user) {
		return true
	}
	if group != nil {
		_, err := loadMembership(ctx, db, *group, user)
		return err == nil
	}
	return false
}

// companyAdminIDs returns the owners and admins of a company, who handle its abuse reports.
func companyAdminIDs(ctx context.Context, db *sql.DB, companyID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id FROM users WHERE company_id = $1 AND company_role IN ('owner', 'admin')
		  AND status = 'active' AND deleted_at IS NULL`, companyID)
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
