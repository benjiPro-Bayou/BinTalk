package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/models"
)

// Voice/video calls use WebRTC: media flows directly between the participants' browsers
// (peer-to-peer; group calls are a full mesh, practical for small groups). The server only
// keeps call state and relays signaling messages (SDP offers/answers, ICE candidates) over the
// WebSocket between participants of the same call.
//
// A huddle (kind "huddle") is a lightweight, audio-first call like Slack's: it does not ring,
// anyone in the conversation can drop in or out at any time, and it ends when the last person
// leaves. Participants can turn their camera on or share their screen while in it.

const ringTimeout = 45 * time.Second

// callGracePeriod is how long a participant may stay in a call without any open WebSocket
// (e.g. a reloading tab) before the server treats them as having left.
const callGracePeriod = 30 * time.Second

const (
	kindCall   = "call"
	kindHuddle = "huddle"
)

type call struct {
	ID           uuid.UUID
	Kind         string // call | huddle
	Media        string // audio | video
	GroupID      *uuid.UUID
	ReceiverID   *uuid.UUID // direct calls
	InitiatorID  uuid.UUID
	Invited      map[uuid.UUID]bool
	Participants map[uuid.UUID]time.Time // user -> joined at
	Joined       map[uuid.UUID]bool      // everyone who was ever in the call
	CreatedAt    time.Time
	StartedAt    *time.Time // when a second person joined
	ringTimer    *time.Timer
	ended        bool
}

// CallManager keeps the in-memory state of active calls.
type CallManager struct {
	mu    sync.Mutex
	calls map[uuid.UUID]*call
	deps  *Dependencies
}

func newCallManager(deps *Dependencies) *CallManager {
	return &CallManager{calls: map[uuid.UUID]*call{}, deps: deps}
}

type callDTO struct {
	ID           uuid.UUID         `json:"id"`
	Kind         string            `json:"kind"`
	Media        string            `json:"media"`
	GroupID      *uuid.UUID        `json:"group_id,omitempty"`
	ReceiverID   *uuid.UUID        `json:"receiver_id,omitempty"`
	Initiator    *models.UserDTO   `json:"initiator"`
	Participants []*models.UserDTO `json:"participants"`
	CreatedAt    time.Time         `json:"created_at"`
	StartedAt    *time.Time        `json:"started_at,omitempty"`
	ICEServers   []iceServer       `json:"ice_servers"`
}

type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// iceServers returns STUN (and optional TURN) servers for WebRTC. TURN is needed when
// participants are behind restrictive NATs/firewalls.
func iceServers() []iceServer {
	stun := os.Getenv("STUN_URLS")
	if stun == "" {
		stun = "stun:stun.l.google.com:19302"
	}
	servers := []iceServer{{URLs: strings.Split(stun, ",")}}
	if turn := os.Getenv("TURN_URLS"); turn != "" {
		servers = append(servers, iceServer{
			URLs: strings.Split(turn, ","), Username: os.Getenv("TURN_USERNAME"), Credential: os.Getenv("TURN_PASSWORD"),
		})
	}
	return servers
}

// callSnapshot is an immutable copy of a call's state, safe to use after m.mu is released.
type callSnapshot struct {
	ID, InitiatorID     uuid.UUID
	Kind, Media         string
	GroupID, ReceiverID *uuid.UUID
	Participants        []uuid.UUID
	Invited             []uuid.UUID
	CreatedAt           time.Time
	StartedAt           *time.Time
}

// snapshot copies the call's state. Caller holds m.mu.
func (c *call) snapshot() callSnapshot {
	s := callSnapshot{
		ID: c.ID, InitiatorID: c.InitiatorID, Kind: c.Kind, Media: c.Media,
		GroupID: c.GroupID, ReceiverID: c.ReceiverID, CreatedAt: c.CreatedAt, StartedAt: c.StartedAt,
		Participants: make([]uuid.UUID, 0, len(c.Participants)), Invited: make([]uuid.UUID, 0, len(c.Invited)),
	}
	for id := range c.Participants {
		s.Participants = append(s.Participants, id)
	}
	for id := range c.Invited {
		s.Invited = append(s.Invited, id)
	}
	return s
}

// dto builds the API view of a call snapshot. Email and role are only included for the viewer;
// pass uuid.Nil to build a DTO that is safe to send to anyone.
func (m *CallManager) dto(ctx context.Context, c callSnapshot, viewer uuid.UUID) *callDTO {
	users := map[uuid.UUID]bool{c.InitiatorID: true}
	for _, id := range c.Participants {
		users[id] = true
	}
	loaded, _ := loadUserDTOs(ctx, m.deps.DB, users)
	public := func(id uuid.UUID) *models.UserDTO {
		if u, ok := loaded[id]; ok {
			dto := *u
			if id != viewer {
				dto.Email, dto.Role, dto.MustChangePassword = "", "", false
			}
			return &dto
		}
		return &models.UserDTO{ID: id}
	}
	d := &callDTO{
		ID: c.ID, Kind: c.Kind, Media: c.Media, GroupID: c.GroupID, ReceiverID: c.ReceiverID,
		Initiator: public(c.InitiatorID), Participants: []*models.UserDTO{},
		CreatedAt: c.CreatedAt, StartedAt: c.StartedAt, ICEServers: iceServers(),
	}
	for _, id := range c.Participants {
		d.Participants = append(d.Participants, public(id))
	}
	return d
}

func (m *CallManager) members(c *call) []uuid.UUID {
	ids := []uuid.UUID{}
	for id := range c.Invited {
		ids = append(ids, id)
	}
	return ids
}

// end finishes a call, notifies everyone invited and records it in the chat. Caller holds m.mu.
func (m *CallManager) endLocked(c *call, reason string) {
	if c.ended {
		return
	}
	c.ended = true
	if c.ringTimer != nil {
		c.ringTimer.Stop()
	}
	delete(m.calls, c.ID)
	m.deps.Hub().SendToUsers(m.members(c), "call.ended", gin.H{"call_id": c.ID, "reason": reason})

	if c.Kind == kindHuddle {
		text := "🎧 Huddle ended"
		if c.StartedAt != nil {
			d := time.Since(*c.StartedAt).Round(time.Second)
			text = fmt.Sprintf("🎧 Huddle · %d:%02d · %d people", int(d.Minutes()), int(d.Seconds())%60, len(c.Joined))
		}
		go postSystemMessage(m.deps, c.snapshot(), text)
		return
	}

	kind := "Voice call"
	if c.Media == "video" {
		kind = "Video call"
	}
	text := "📞 Missed " + strings.ToLower(kind)
	if c.StartedAt != nil {
		d := time.Since(*c.StartedAt).Round(time.Second)
		text = fmt.Sprintf("📞 %s · %d:%02d", kind, int(d.Minutes()), int(d.Seconds())%60)
	} else if reason == "declined" {
		text = "📞 Declined " + strings.ToLower(kind)
	} else if reason == "cancelled" {
		text = "📞 Cancelled " + strings.ToLower(kind)
	}
	go postSystemMessage(m.deps, c.snapshot(), text)
}

// Signal relays a WebRTC signaling payload between two participants who have joined the call.
func (m *CallManager) Signal(from uuid.UUID, raw json.RawMessage) {
	var msg struct {
		CallID uuid.UUID       `json:"call_id"`
		To     uuid.UUID       `json:"to"`
		Data   json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &msg) != nil || len(msg.Data) > 64<<10 {
		return
	}
	m.mu.Lock()
	c, ok := m.calls[msg.CallID]
	allowed := false
	if ok {
		_, fromIn := c.Participants[from]
		_, toIn := c.Participants[msg.To]
		allowed = fromIn && toIn && from != msg.To
	}
	m.mu.Unlock()
	if !allowed {
		return
	}
	m.deps.Hub().SendToUsers([]uuid.UUID{msg.To}, "call.signal",
		gin.H{"call_id": msg.CallID, "from": from, "data": msg.Data})
}

// CallHandler serves the call REST endpoints.
type CallHandler struct {
	deps *Dependencies
}

// NewCallHandler creates a CallHandler.
func NewCallHandler(deps *Dependencies) *CallHandler {
	return &CallHandler{deps: deps}
}

// StartCall rings the other person (receiver_id) or every member of a group (group_id), or
// starts a huddle there (kind "huddle"). The caller joins immediately.
func (h *CallHandler) StartCall(c *gin.Context) {
	var req struct {
		ReceiverID *uuid.UUID `json:"receiver_id"`
		GroupID    *uuid.UUID `json:"group_id"`
		Media      string     `json:"media" binding:"omitempty,oneof=audio video"`
		Kind       string     `json:"kind" binding:"omitempty,oneof=call huddle"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if req.Kind == "" {
		req.Kind = kindCall
	}
	if req.Kind == kindHuddle {
		req.Media = "audio" // huddles start audio-only; cameras and screens can be turned on inside
	}
	if req.Media == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "media must be audio or video"})
		return
	}
	if (req.ReceiverID == nil) == (req.GroupID == nil) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exactly one of receiver_id or group_id is required"})
		return
	}

	ctx := c.Request.Context()
	caller, ok := currentActor(c, h.deps)
	if !ok {
		return
	}
	me := caller.ID
	invited := map[uuid.UUID]bool{me: true}
	if req.ReceiverID != nil {
		if *req.ReceiverID == me {
			c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot call yourself"})
			return
		}
		user, err := loadColleague(ctx, h.deps.DB, caller.CompanyID, *req.ReceiverID)
		if errors.Is(err, errNotFound) || (err == nil && !user.IsActive()) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if err != nil {
			h.deps.internalError(c, err, "load callee")
			return
		}
		invited[user.ID] = true
	} else {
		if _, err := loadMembership(ctx, h.deps.DB, *req.GroupID, me); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
			return
		}
		ids, err := groupMemberIDs(ctx, h.deps.DB, *req.GroupID)
		if err != nil {
			h.deps.internalError(c, err, "load group members")
			return
		}
		for _, id := range ids {
			invited[id] = true
		}
	}

	m := h.deps.Calls()
	m.mu.Lock()
	// One call or huddle per conversation at a time: the client joins the ongoing one instead.
	for _, existing := range m.calls {
		if sameConversation(existing, req.GroupID, me, req.ReceiverID) {
			m.mu.Unlock()
			what := "a call"
			if existing.Kind == kindHuddle {
				what = "a huddle"
			}
			c.JSON(http.StatusConflict, gin.H{"error": what + " is already ongoing in this conversation",
				"call_id": existing.ID, "kind": existing.Kind})
			return
		}
	}
	call := &call{
		ID: uuid.New(), Kind: req.Kind, Media: req.Media, GroupID: req.GroupID, ReceiverID: req.ReceiverID,
		InitiatorID: me, Invited: invited, Participants: map[uuid.UUID]time.Time{me: time.Now()},
		Joined: map[uuid.UUID]bool{me: true}, CreatedAt: time.Now(),
	}
	m.calls[call.ID] = call
	if call.Kind == kindCall {
		call.ringTimer = time.AfterFunc(ringTimeout, func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if !call.ended && call.StartedAt == nil {
				m.endLocked(call, "missed")
			}
		})
	}
	snap := call.snapshot()
	m.mu.Unlock()

	others := []uuid.UUID{}
	for id := range invited {
		if id != me {
			others = append(others, id)
		}
	}
	// Invitees get a DTO without the caller's email and role.
	h.deps.Hub().SendToUsers(others, "call.incoming", m.dto(ctx, snap, uuid.Nil))
	c.JSON(http.StatusCreated, gin.H{"call": m.dto(ctx, snap, me)})
}

// sameConversation reports whether an ongoing call belongs to the group, or to the direct
// conversation between a and b.
func sameConversation(existing *call, groupID *uuid.UUID, a uuid.UUID, b *uuid.UUID) bool {
	if groupID != nil || existing.GroupID != nil {
		return groupID != nil && existing.GroupID != nil && *groupID == *existing.GroupID
	}
	if b == nil || existing.ReceiverID == nil {
		return false
	}
	x, y := existing.InitiatorID, *existing.ReceiverID
	return (x == a && y == *b) || (x == *b && y == a)
}

func (h *CallHandler) loadCall(c *gin.Context) (*CallManager, *call, uuid.UUID, bool) {
	id, ok := uuidParam(c, "id")
	if !ok {
		return nil, nil, uuid.Nil, false
	}
	me := middleware.GetUserID(c)
	m := h.deps.Calls()
	m.mu.Lock()
	call, found := m.calls[id]
	if !found || !call.Invited[me] {
		m.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "this call has ended"})
		return nil, nil, uuid.Nil, false
	}
	return m, call, me, true // m.mu stays locked; callers unlock
}

// JoinCall answers/joins a call. The response lists the participants already in it; the joiner
// sends each of them a WebRTC offer.
func (h *CallHandler) JoinCall(c *gin.Context) {
	m, call, me, ok := h.loadCall(c)
	if !ok {
		return
	}
	call.Participants[me] = time.Now()
	call.Joined[me] = true
	if call.StartedAt == nil && len(call.Participants) >= 2 {
		now := time.Now()
		call.StartedAt = &now
	}
	others := []uuid.UUID{}
	for id := range call.Invited {
		if id != me {
			others = append(others, id)
		}
	}
	snap := call.snapshot()
	m.mu.Unlock()

	ctx := c.Request.Context()
	dto := m.dto(ctx, snap, me)
	user, _ := loadUser(ctx, h.deps.DB, me)
	var joined *models.UserDTO
	if user != nil {
		joined = publicUserDTO(user, uuid.Nil)
	}
	// Everyone invited (including the joiner's other tabs) learns who joined.
	h.deps.Hub().SendToUsers(append(others, me), "call.participant_joined",
		gin.H{"call_id": snap.ID, "user": joined, "started_at": snap.StartedAt})
	c.JSON(http.StatusOK, gin.H{"call": dto})
}

// DeclineCall rejects an incoming call. Declining a direct call ends it.
func (h *CallHandler) DeclineCall(c *gin.Context) {
	m, call, me, ok := h.loadCall(c)
	if !ok {
		return
	}
	defer m.mu.Unlock()
	if call.Kind == kindCall && call.GroupID == nil && call.StartedAt == nil {
		m.endLocked(call, "declined")
	} else {
		h.deps.Hub().SendToUsers([]uuid.UUID{me}, "call.dismissed", gin.H{"call_id": call.ID})
	}
	c.JSON(http.StatusOK, gin.H{"declined": true})
}

// LeaveCall hangs up. A direct call ends when either side leaves; group calls and huddles end
// when the last participant leaves.
func (h *CallHandler) LeaveCall(c *gin.Context) {
	m, call, me, ok := h.loadCall(c)
	if !ok {
		return
	}
	defer m.mu.Unlock()
	m.leaveLocked(call, me)
	c.JSON(http.StatusOK, gin.H{"left": true})
}

// leaveLocked removes a participant from a call, ending it when appropriate. Caller holds m.mu.
func (m *CallManager) leaveLocked(call *call, userID uuid.UUID) {
	delete(call.Participants, userID)
	switch {
	case len(call.Participants) == 0:
		m.endLocked(call, "hung_up")
	case call.Kind == kindHuddle:
		m.deps.Hub().SendToUsers(m.members(call), "call.participant_left", gin.H{"call_id": call.ID, "user_id": userID})
	case call.GroupID == nil && call.StartedAt == nil && userID == call.InitiatorID:
		m.endLocked(call, "cancelled")
	case call.GroupID == nil:
		m.endLocked(call, "hung_up")
	default:
		m.deps.Hub().SendToUsers(m.members(call), "call.participant_left", gin.H{"call_id": call.ID, "user_id": userID})
	}
}

// DropUser takes a user out of every call they are in (e.g. after their last WebSocket closed
// for longer than callGracePeriod, or their account was suspended).
func (m *CallManager) DropUser(userID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, call := range m.calls {
		if _, in := call.Participants[userID]; in {
			m.leaveLocked(call, userID)
		}
	}
}

// addToGroupCalls invites a new group member to calls already ongoing in the group.
func (m *CallManager) addToGroupCalls(groupID, userID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, call := range m.calls {
		if call.GroupID != nil && *call.GroupID == groupID {
			call.Invited[userID] = true
		}
	}
}

// MuteParticipant lets a group admin (or a moderator, for plain members) turn off someone's
// microphone in a group call. Media is peer-to-peer, so the muted person's own app does the
// muting; they can unmute themselves again, as in other meeting apps.
func (h *CallHandler) MuteParticipant(c *gin.Context) {
	var req struct {
		UserID uuid.UUID `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	m, call, me, ok := h.loadCall(c)
	if !ok {
		return
	}
	_, inCall := call.Participants[req.UserID]
	_, meInCall := call.Participants[me]
	groupID, members := call.GroupID, m.members(call)
	m.mu.Unlock()

	if groupID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only group calls can be moderated"})
		return
	}
	if !inCall || !meInCall {
		c.JSON(http.StatusConflict, gin.H{"error": "you and that person both need to be in the call"})
		return
	}
	if !moderationCheck(c, h.deps, *groupID, me, req.UserID, "only group admins can mute others") {
		return
	}
	var by *models.UserDTO
	if user, err := loadUser(c.Request.Context(), h.deps.DB, me); err == nil {
		by = publicUserDTO(user, uuid.Nil)
	}
	h.deps.Hub().SendToUsers(members, "call.muted", gin.H{"call_id": call.ID, "user_id": req.UserID, "by": by})
	c.JSON(http.StatusOK, gin.H{"muted": true})
}

// removeFromGroupCalls drops someone who was removed from a group out of any call in it.
func (m *CallManager) removeFromGroupCalls(groupID, userID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, call := range m.calls {
		if call.GroupID == nil || *call.GroupID != groupID || !call.Invited[userID] {
			continue
		}
		delete(call.Invited, userID)
		_, wasIn := call.Participants[userID]
		delete(call.Participants, userID)
		m.deps.Hub().SendToUsers([]uuid.UUID{userID}, "call.ended", gin.H{"call_id": call.ID, "reason": "removed"})
		switch {
		case wasIn && len(call.Participants) == 0:
			m.endLocked(call, "hung_up")
		case wasIn:
			m.deps.Hub().SendToUsers(m.members(call), "call.participant_left", gin.H{"call_id": call.ID, "user_id": userID})
		}
	}
}

// ActiveCalls lists ongoing calls the caller is invited to (e.g. to show "Join" in a group).
func (h *CallHandler) ActiveCalls(c *gin.Context) {
	me := middleware.GetUserID(c)
	m := h.deps.Calls()
	m.mu.Lock()
	var mine []callSnapshot
	for _, call := range m.calls {
		if call.Invited[me] {
			mine = append(mine, call.snapshot())
		}
	}
	m.mu.Unlock()
	out := []*callDTO{}
	for _, snap := range mine {
		out = append(out, m.dto(c.Request.Context(), snap, me))
	}
	c.JSON(http.StatusOK, gin.H{"calls": out})
}

// postSystemMessage records a call in the conversation ("📞 Video call · 3:12").
func postSystemMessage(deps *Dependencies, c callSnapshot, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ciphertext, iv, tag, keyVersion, err := deps.EncryptionService.EncryptField([]byte(text))
	if err != nil {
		deps.Logger.WithError(err).Warn("Failed to encrypt call message")
		return
	}
	msg, err := scanMessage(deps.DB.QueryRowContext(ctx, `
		INSERT INTO messages AS m (sender_id, receiver_id, group_id, content_encrypted, content_iv, content_tag,
			message_type, key_version)
		VALUES ($1, $2, $3, $4, $5, $6, 'system', $7)
		RETURNING `+messageColumns, c.InitiatorID, c.ReceiverID, c.GroupID, ciphertext, iv, tag, keyVersion))
	if err != nil {
		deps.Logger.WithError(err).Warn("Failed to record call message")
		return
	}
	if c.ReceiverID != nil {
		a, b := c.InitiatorID, *c.ReceiverID
		if a.String() > b.String() {
			a, b = b, a
		}
		_, _ = deps.DB.ExecContext(ctx, `INSERT INTO conversations (user_id_1, user_id_2) VALUES ($1, $2)
			ON CONFLICT (user_id_1, user_id_2) DO NOTHING`, a, b)
	}
	sender, err := loadUser(ctx, deps.DB, c.InitiatorID)
	if err != nil {
		return
	}
	dto := msg.ToDTO(sender)
	dto.Sender = publicUserDTO(sender, uuid.Nil)
	dto.Content = text
	deps.Hub().SendToUsers(c.Invited, "message.new", dto)
}
