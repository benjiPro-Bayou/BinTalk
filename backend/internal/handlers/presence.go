package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/bintalk/bintalk-clone/internal/middleware"
)

// Presence is derived from WebSocket connections:
//
//   - offline: no open connection, or the user chose to appear offline
//   - away:    the user chose "away", or every connection reports the user idle
//   - active:  otherwise
//
// Every change is broadcast to the connected clients of the same company as "presence.updated";
// a new connection first receives a "presence.snapshot" of everyone in its company who is not
// offline. Presence never crosses companies.

const (
	presenceActive  = "active"
	presenceAway    = "away"
	presenceOffline = "offline"
)

var presencePreferences = map[string]bool{"auto": true, presenceAway: true, presenceOffline: true}

// presenceLocked computes a user's status. Caller holds h.mu.
func (h *Hub) presenceLocked(id uuid.UUID) string {
	conns := h.clients[id]
	if len(conns) == 0 {
		return presenceOffline
	}
	switch h.prefs[id] {
	case presenceOffline:
		return presenceOffline
	case presenceAway:
		return presenceAway
	}
	for c := range conns {
		if !c.idle {
			return presenceActive
		}
	}
	return presenceAway
}

// updatePresenceLocked recomputes a user's status and broadcasts it if it changed. Broadcasting
// under the lock keeps updates in order; sends never block. Caller holds h.mu for writing.
func (h *Hub) updatePresenceLocked(id uuid.UUID) {
	status := h.presenceLocked(id)
	previous, ok := h.status[id]
	if !ok {
		previous = presenceOffline
	}
	if status == previous {
		return
	}
	if status == presenceOffline {
		delete(h.status, id)
	} else {
		h.status[id] = status
	}
	payload, err := json.Marshal(wsEvent{Type: "presence.updated",
		Data: gin.H{"user_id": id, "status": status}, Timestamp: time.Now().UTC()})
	if err != nil {
		return
	}
	company := h.companyOf[id]
	for _, conns := range h.clients {
		for c := range conns {
			if c.companyID == company {
				h.sendLocked(c, payload)
			}
		}
	}
}

// setIdle records whether the user is idle on one connection.
func (h *Hub) setIdle(c *wsClient, idle bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c.userID][c]; !ok {
		return
	}
	c.idle = idle
	h.updatePresenceLocked(c.userID)
}

// ensurePreference loads a user's presence preference into the cache (once per process).
func (h *Hub) ensurePreference(ctx context.Context, id uuid.UUID) {
	h.mu.RLock()
	_, cached := h.prefs[id]
	h.mu.RUnlock()
	if cached || h.loadPreference == nil {
		return
	}
	pref := h.loadPreference(ctx, id)
	h.mu.Lock()
	if _, ok := h.prefs[id]; !ok {
		h.prefs[id] = pref
	}
	h.mu.Unlock()
}

// sendSnapshot gives a new connection everyone's current status and the user's own preference.
func (h *Hub) sendSnapshot(c *wsClient) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	statuses := make(map[uuid.UUID]string, len(h.status))
	for id, s := range h.status {
		if h.companyOf[id] == c.companyID {
			statuses[id] = s
		}
	}
	pref := h.prefs[c.userID]
	if pref == "" {
		pref = "auto"
	}
	payload, err := json.Marshal(wsEvent{Type: "presence.snapshot",
		Data: gin.H{"statuses": statuses, "preference": pref}, Timestamp: time.Now().UTC()})
	if err != nil {
		return
	}
	h.sendLocked(c, payload)
}

// setPreference changes the status a user chose and tells their other tabs/devices.
func (h *Hub) setPreference(id uuid.UUID, pref string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prefs[id] = pref
	if payload, err := json.Marshal(wsEvent{Type: "presence.preference",
		Data: gin.H{"preference": pref}, Timestamp: time.Now().UTC()}); err == nil {
		for c := range h.clients[id] {
			h.sendLocked(c, payload)
		}
	}
	h.updatePresenceLocked(id)
}

func loadPresencePreference(deps *Dependencies) func(context.Context, uuid.UUID) string {
	return func(ctx context.Context, id uuid.UUID) string {
		var pref string
		err := deps.DB.QueryRowContext(ctx,
			`SELECT COALESCE(presence_preference, 'auto') FROM users WHERE id = $1`, id).Scan(&pref)
		if err != nil || !presencePreferences[pref] {
			return "auto"
		}
		return pref
	}
}

// PresenceHandler lets users choose their status.
type PresenceHandler struct {
	deps *Dependencies
}

// NewPresenceHandler creates a PresenceHandler.
func NewPresenceHandler(deps *Dependencies) *PresenceHandler {
	return &PresenceHandler{deps: deps}
}

// SetPreference handles PUT /presence {"preference": "auto" | "away" | "offline"}.
func (h *PresenceHandler) SetPreference(c *gin.Context) {
	var req struct {
		Preference string `json:"preference" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if !presencePreferences[req.Preference] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "preference must be auto, away or offline"})
		return
	}
	me := middleware.GetUserID(c)
	if _, err := h.deps.DB.ExecContext(c.Request.Context(),
		`UPDATE users SET presence_preference = $1 WHERE id = $2`, req.Preference, me); err != nil {
		h.deps.internalError(c, err, "save presence preference")
		return
	}
	h.deps.Hub().setPreference(me, req.Preference)
	c.JSON(http.StatusOK, gin.H{"preference": req.Preference})
}
