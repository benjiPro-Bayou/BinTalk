package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/bintalk/bintalk-clone/internal/middleware"
)

const (
	wsWriteTimeout = 10 * time.Second
	wsPongTimeout  = 60 * time.Second
	wsPingInterval = 30 * time.Second
	wsMaxMessage   = 4096
	wsSendBuffer   = 64

	// wsMaxConnsPerUser caps open sockets per user (tabs and devices).
	wsMaxConnsPerUser = 10
	// Client frames per second a socket may send (sustained, and in a burst); extra frames are dropped.
	wsFrameRate  = 20
	wsFrameBurst = 60

	// wsTicketTTL is how long a WebSocket ticket from POST /ws-ticket can be used (once).
	wsTicketTTL = 30 * time.Second
)

// wsEvent is the envelope for every message pushed to WebSocket clients.
type wsEvent struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

type wsClient struct {
	userID    uuid.UUID
	companyID uuid.UUID // presence is only shared within a company
	tokenKey  string    // Redis key of the access token the socket was opened with
	conn      *websocket.Conn
	send      chan []byte
	idle      bool // the user has been inactive on this connection (guarded by Hub.mu)
	closed    bool // send has been closed (guarded by Hub.mu); only closeLocked closes it
}

// Hub tracks connected WebSocket clients and delivers events to users.
type Hub struct {
	mu      sync.RWMutex
	clients map[uuid.UUID]map[*wsClient]struct{}
	logger  *logrus.Logger

	// Presence (see presence.go).
	companyOf      map[uuid.UUID]uuid.UUID // user -> company, learned when they connect
	status         map[uuid.UUID]string    // last broadcast status of users who are not offline
	prefs          map[uuid.UUID]string    // the status each user chose: auto | away | offline
	loadPreference func(context.Context, uuid.UUID) string
}

func newHub(logger *logrus.Logger) *Hub {
	return &Hub{
		clients: make(map[uuid.UUID]map[*wsClient]struct{}), logger: logger,
		status: make(map[uuid.UUID]string), prefs: make(map[uuid.UUID]string),
		companyOf: make(map[uuid.UUID]uuid.UUID),
	}
}

// closeLocked closes a client's send channel once. Caller holds h.mu for writing.
func (h *Hub) closeLocked(c *wsClient) {
	if !c.closed {
		c.closed = true
		close(c.send)
	}
}

// sendLocked queues a payload without blocking; it reports false if the client is closed or its
// buffer is full. Caller holds h.mu (read or write), so the channel cannot be closed meanwhile.
func (h *Hub) sendLocked(c *wsClient, payload []byte) bool {
	if c.closed {
		return false
	}
	select {
	case c.send <- payload:
		return true
	default:
		return false
	}
}

func (h *Hub) send(c *wsClient, payload []byte) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sendLocked(c, payload)
}

// register adds a client, or reports false if the user already has too many connections.
func (h *Hub) register(c *wsClient) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.clients[c.userID]) >= wsMaxConnsPerUser {
		return false
	}
	if h.clients[c.userID] == nil {
		h.clients[c.userID] = make(map[*wsClient]struct{})
	}
	h.clients[c.userID][c] = struct{}{}
	h.companyOf[c.userID] = c.companyID
	h.updatePresenceLocked(c.userID)
	return true
}

// unregister removes a client and reports whether the user has no connections left.
func (h *Hub) unregister(c *wsClient) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if conns, ok := h.clients[c.userID]; ok {
		if _, ok := conns[c]; ok {
			delete(conns, c)
			h.closeLocked(c)
		}
		if len(conns) == 0 {
			delete(h.clients, c.userID)
		}
	}
	h.updatePresenceLocked(c.userID)
	return len(h.clients[c.userID]) == 0
}

// connected reports whether the user has at least one open connection.
func (h *Hub) connected(userID uuid.UUID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients[userID]) > 0
}

// SendToUsers delivers an event to every connection of the given users.
// Slow clients whose buffers are full miss the event rather than blocking the sender.
func (h *Hub) SendToUsers(userIDs []uuid.UUID, eventType string, data interface{}) {
	payload, err := json.Marshal(wsEvent{Type: eventType, Data: data, Timestamp: time.Now().UTC()})
	if err != nil {
		h.logger.WithError(err).Warn("Failed to encode WebSocket event")
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	seen := make(map[uuid.UUID]bool, len(userIDs))
	for _, id := range userIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		for client := range h.clients[id] {
			if !h.sendLocked(client, payload) && !client.closed {
				h.logger.WithField("user_id", id).Warn("WebSocket client buffer full; dropping event")
			}
		}
	}
}

// DisconnectUser closes every WebSocket connection of a user (e.g. after suspension). Events
// already queued, such as the suspension notice, are still delivered before the close.
func (h *Hub) DisconnectUser(userID uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients[userID] {
		h.closeLocked(c)
	}
	delete(h.clients, userID)
	h.updatePresenceLocked(userID)
}

// CloseAll closes every connection (on shutdown).
func (h *Hub) CloseAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for userID, conns := range h.clients {
		for c := range conns {
			h.closeLocked(c)
		}
		delete(h.clients, userID)
	}
}

// DisconnectSession closes the user's connections that were opened with one access token
// (identified by its Redis key), e.g. on logout.
func (h *Hub) DisconnectSession(userID uuid.UUID, tokenKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	conns := h.clients[userID]
	for c := range conns {
		if c.tokenKey == tokenKey {
			h.closeLocked(c)
			delete(conns, c)
		}
	}
	if len(conns) == 0 {
		delete(h.clients, userID)
	}
	h.updatePresenceLocked(userID)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Connections are authenticated with an access token (not cookies), so
	// cross-origin connections cannot ride on a victim's session.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WebSocketHandler serves real-time event streams.
type WebSocketHandler struct {
	deps *Dependencies
}

// NewWebSocketHandler creates a WebSocketHandler.
func NewWebSocketHandler(deps *Dependencies) *WebSocketHandler {
	return &WebSocketHandler{deps: deps}
}

func wsTicketKey(ticket string) string {
	return "auth:wsticket:" + hashToken(ticket)
}

// IssueTicket handles POST /ws-ticket: it returns a single-use ticket, valid for 30 seconds, that
// opens a WebSocket for the caller's session. Browsers cannot set headers on WebSocket requests,
// and a ticket in the URL is harmless in access logs, unlike the access token itself.
func (h *WebSocketHandler) IssueTicket(c *gin.Context) {
	ticket, err := randomToken()
	if err != nil {
		h.deps.internalError(c, err, "generate websocket ticket")
		return
	}
	key := middleware.AccessTokenKey(middleware.BearerToken(c))
	if err := h.deps.Redis.Set(c.Request.Context(), wsTicketKey(ticket), key, wsTicketTTL).Err(); err != nil {
		h.deps.internalError(c, err, "store websocket ticket")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ticket": ticket, "expires_in": int(wsTicketTTL.Seconds())})
}

// HandleConnection upgrades GET /ws/chat/:userId to a WebSocket. It is authenticated with
// ?ticket=<ticket> from POST /ws-ticket (browsers) or an "Authorization: Bearer" header, and the
// session must belong to :userId. The session is rechecked periodically; the socket closes when it
// expires or is revoked.
func (h *WebSocketHandler) HandleConnection(c *gin.Context) {
	userID, ok := uuidParam(c, "userId")
	if !ok {
		return
	}

	ctx := c.Request.Context()
	var tokenKey string
	if ticket := c.Query("ticket"); ticket != "" {
		key, err := h.deps.Redis.GetDel(ctx, wsTicketKey(ticket)).Result()
		if errors.Is(err, redis.Nil) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired ticket"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "ticket lookup failed")
			return
		}
		tokenKey = key
	} else if token := middleware.BearerToken(c); token != "" {
		tokenKey = middleware.AccessTokenKey(token)
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing ticket or bearer token"})
		return
	}

	session, err := middleware.LookupSessionByKey(ctx, h.deps.Redis, h.deps.DB, tokenKey)
	if errors.Is(err, middleware.ErrInvalidToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		h.deps.internalError(c, err, "token lookup failed")
		return
	}
	if session.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "token does not belong to this user"})
		return
	}
	if session.MustChangePassword {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you must change your password before continuing",
			"code":  "password_change_required",
		})
		return
	}
	hub := h.deps.Hub()
	user, err := loadUser(ctx, h.deps.DB, userID)
	if err != nil {
		h.deps.internalError(c, err, "load user")
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		// Upgrade has already written an HTTP error response.
		h.deps.Logger.WithError(err).Debug("WebSocket upgrade failed")
		return
	}

	client := &wsClient{userID: userID, companyID: user.CompanyID, tokenKey: tokenKey, conn: conn,
		send: make(chan []byte, wsSendBuffer)}
	hub.ensurePreference(ctx, userID)
	if !hub.register(client) {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "too many connections"),
			time.Now().Add(wsWriteTimeout))
		conn.Close()
		return
	}
	h.deps.Logger.WithField("user_id", userID).Info("WebSocket connected")

	if payload, err := json.Marshal(wsEvent{Type: "connected", Data: gin.H{"user_id": userID}, Timestamp: time.Now().UTC()}); err == nil {
		hub.send(client, payload)
	}
	hub.sendSnapshot(client)

	go client.writePump(func() bool { return h.sessionValid(tokenKey, userID) })
	lastConnection := client.readPump(hub, func(msgType string, raw []byte) {
		if msgType == "call.signal" {
			h.deps.Calls().Signal(userID, raw)
		}
	})
	if lastConnection {
		h.onDisconnected(userID)
	}
	h.deps.Logger.WithField("user_id", userID).Info("WebSocket disconnected")
}

// sessionValid reports whether a socket's session is still usable. Only a definite "invalid"
// closes the socket; a transient Redis or database error does not.
func (h *WebSocketHandler) sessionValid(tokenKey string, userID uuid.UUID) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := middleware.LookupSessionByKey(ctx, h.deps.Redis, h.deps.DB, tokenKey)
	if errors.Is(err, middleware.ErrInvalidToken) {
		return false
	}
	if err != nil {
		h.deps.Logger.WithError(err).Warn("WebSocket session check failed")
		return true
	}
	return session.UserID == userID && !session.MustChangePassword
}

// onDisconnected takes a user out of their calls once they have had no connection for
// callGracePeriod (a reload reconnects well within it).
func (h *WebSocketHandler) onDisconnected(userID uuid.UUID) {
	time.AfterFunc(callGracePeriod, func() {
		if !h.deps.Hub().connected(userID) {
			h.deps.Calls().DropUser(userID)
		}
	})
}

// readPump consumes client frames until the connection closes. Chat messages are sent over
// REST; client frames are {"type":"ping"}, {"type":"presence.activity","idle":bool} and call
// signaling ({"type":"call.signal",...}), which is passed to onMessage.
func (c *wsClient) readPump(hub *Hub, onMessage func(msgType string, raw []byte)) (lastConnection bool) {
	defer func() {
		lastConnection = hub.unregister(c)
		c.conn.Close()
	}()
	limiter := rate.NewLimiter(wsFrameRate, wsFrameBurst)

	c.conn.SetReadLimit(wsMaxMessage * 16) // SDP offers can be a few KB
	_ = c.conn.SetReadDeadline(time.Now().Add(wsPongTimeout))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(wsPongTimeout))
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(wsPongTimeout))
		if !limiter.Allow() {
			continue
		}

		var msg struct {
			Type string `json:"type"`
			Idle bool   `json:"idle"`
		}
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		switch msg.Type {
		case "call.signal":
			onMessage(msg.Type, data)
		case "presence.activity":
			hub.setIdle(c, msg.Idle)
		case "ping":
			if payload, err := json.Marshal(wsEvent{Type: "pong", Timestamp: time.Now().UTC()}); err == nil {
				hub.send(c, payload)
			}
		}
	}
}

// writePump sends queued events and keep-alive pings until the send channel closes. With every
// ping it rechecks the session and closes the socket once valid reports false.
func (c *wsClient) writePump(valid func() bool) {
	ticker := time.NewTicker(wsPingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case payload, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		case <-ticker.C:
			if !valid() {
				_ = c.conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "session ended"),
					time.Now().Add(wsWriteTimeout))
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
