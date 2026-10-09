package handlers

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func testDeps() *Dependencies {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return &Dependencies{Logger: logger}
}

// fakeClient registers a socket-less client so tests can observe what the hub sends a user.
func fakeClient(t *testing.T, hub *Hub, userID uuid.UUID) *wsClient {
	t.Helper()
	c := &wsClient{userID: userID, send: make(chan []byte, wsSendBuffer)}
	if !hub.register(c) {
		t.Fatal("register failed")
	}
	return c
}

func drain(c *wsClient) []string {
	var types []string
	for {
		select {
		case payload, ok := <-c.send:
			if !ok {
				return types
			}
			var e wsEvent
			_ = json.Unmarshal(payload, &e)
			types = append(types, e.Type)
		default:
			return types
		}
	}
}

// REL-001: snapshots are taken under the lock, so readers never iterate a map that joins and
// leaves are writing. Before the fix this crashed with "concurrent map iteration and map write".
func TestCallSnapshotsAreSafeDuringJoinsAndLeaves(t *testing.T) {
	m := newCallManager(testDeps())
	group := uuid.New()
	c := &call{
		ID: uuid.New(), Kind: kindHuddle, GroupID: &group, InitiatorID: uuid.New(),
		Invited: map[uuid.UUID]bool{}, Participants: map[uuid.UUID]time.Time{}, Joined: map[uuid.UUID]bool{},
	}
	keep := uuid.New() // keeps the call from ending
	c.Participants[keep] = time.Now()
	m.calls[c.ID] = c

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				id := uuid.New()
				m.mu.Lock()
				c.Invited[id] = true
				c.Participants[id] = time.Now()
				m.mu.Unlock()
				m.mu.Lock()
				m.leaveLocked(c, id)
				m.mu.Unlock()
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		m.mu.Lock()
		snap := c.snapshot()
		m.mu.Unlock()
		for range snap.Participants { // iterating outside the lock must be safe
		}
	}
	close(stop)
	wg.Wait()
}

// REL-006: signaling is relayed only between people who have joined the call.
func TestSignalOnlyBetweenJoinedParticipants(t *testing.T) {
	deps := testDeps()
	m := deps.Calls()
	a, b, invitee := uuid.New(), uuid.New(), uuid.New()
	c := &call{
		ID: uuid.New(), Kind: kindCall, InitiatorID: a,
		Invited:      map[uuid.UUID]bool{a: true, b: true, invitee: true},
		Participants: map[uuid.UUID]time.Time{a: time.Now(), b: time.Now()},
		Joined:       map[uuid.UUID]bool{a: true, b: true},
	}
	m.calls[c.ID] = c
	toB := fakeClient(t, deps.Hub(), b)
	toInvitee := fakeClient(t, deps.Hub(), invitee)
	drain(toB)
	drain(toInvitee)

	signal := func(from, to uuid.UUID) {
		raw, _ := json.Marshal(map[string]interface{}{"call_id": c.ID, "to": to, "data": map[string]string{"type": "offer"}})
		m.Signal(from, raw)
	}
	signal(a, b)
	if got := drain(toB); len(got) != 1 || got[0] != "call.signal" {
		t.Fatalf("participant did not get the signal: %v", got)
	}
	signal(a, invitee)
	if got := drain(toInvitee); len(got) != 0 {
		t.Fatalf("an invitee who has not joined got signaling: %v", got)
	}
	signal(invitee, b)
	if got := drain(toB); len(got) != 0 {
		t.Fatalf("signaling from an invitee who has not joined was relayed: %v", got)
	}
}

// REL-006: a user dropped from a group call (e.g. after losing their connection) leaves it.
func TestDropUserLeavesGroupCall(t *testing.T) {
	deps := testDeps()
	m := deps.Calls()
	group := uuid.New()
	a, b, c3 := uuid.New(), uuid.New(), uuid.New()
	c := &call{
		ID: uuid.New(), Kind: kindCall, GroupID: &group, InitiatorID: a,
		Invited:      map[uuid.UUID]bool{a: true, b: true, c3: true},
		Participants: map[uuid.UUID]time.Time{a: time.Now(), b: time.Now(), c3: time.Now()},
		Joined:       map[uuid.UUID]bool{a: true, b: true, c3: true},
	}
	m.calls[c.ID] = c
	observer := fakeClient(t, deps.Hub(), a)
	drain(observer)

	m.DropUser(b)
	if _, in := c.Participants[b]; in {
		t.Fatal("dropped user is still a participant")
	}
	if got := drain(observer); len(got) != 1 || got[0] != "call.participant_left" {
		t.Fatalf("others were not told: %v", got)
	}

	m.addToGroupCalls(group, uuid.New())
	if len(c.Invited) != 4 {
		t.Fatal("a new group member was not invited to the ongoing call")
	}
}

// REL-002: closing a user's connections and sending to them afterwards must not panic.
func TestHubSendAfterDisconnectDoesNotPanic(t *testing.T) {
	hub := newHub(testDeps().Logger)
	user := uuid.New()
	c := fakeClient(t, hub, user)
	other := fakeClient(t, hub, user)
	other.tokenKey = "auth:token:x"

	hub.DisconnectSession(user, "auth:token:x")
	if !other.closed || c.closed {
		t.Fatal("DisconnectSession closed the wrong connections")
	}
	hub.DisconnectUser(user)
	if hub.send(c, []byte(`{}`)) {
		t.Fatal("send to a closed client reported success")
	}
	hub.SendToUsers([]uuid.UUID{user}, "x", nil)
	hub.unregister(c) // after DisconnectUser: must not close the channel twice
	hub.CloseAll()
}

func TestHubCapsConnectionsPerUser(t *testing.T) {
	hub := newHub(testDeps().Logger)
	user := uuid.New()
	for i := 0; i < wsMaxConnsPerUser; i++ {
		fakeClient(t, hub, user)
	}
	if hub.register(&wsClient{userID: user, send: make(chan []byte, 1)}) {
		t.Fatal("registered more connections than allowed")
	}
}
