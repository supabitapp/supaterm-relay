package e2e

import (
	"fmt"
	"sync"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

func TestMultipleHostsNoCrossDelivery(t *testing.T) {
	r := startRelay(t)
	const hosts, clients, rounds = 3, 8, 50
	hs := make([]*endpoint.Host, hosts)
	for i := range hs {
		hs[i] = register(t, r)
		go func(i int, h *endpoint.Host) {
			for ev := range h.Events {
				if ev.Type != "incoming" {
					continue
				}
				ws, _, err := h.Accept(ev)
				if err != nil {
					continue
				}
				go func() {
					defer ws.Close()
					for {
						typ, data, err := ws.ReadMessage()
						if err != nil {
							return
						}
						if ws.WriteMessage(typ, append([]byte(fmt.Sprintf("h%d:", i)), data...)) != nil {
							return
						}
					}
				}()
			}
		}(i, hs[i])
	}

	var wg sync.WaitGroup
	errs := make(chan error, hosts*clients)
	for i := range hosts {
		for c := range clients {
			wg.Go(func() {
				ws, resp, err := endpoint.Connect(r.base, hs[i].ID)
				if err != nil {
					errs <- fmt.Errorf("connect %d/%d: %v %s", i, c, err, status(resp))
					return
				}
				defer ws.Close()
				for k := range rounds {
					msg := fmt.Sprintf("c-%d-%d-%d", i, c, k)
					if err := ws.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
						errs <- err
						return
					}
					_, got, err := ws.ReadMessage()
					if err != nil {
						errs <- err
						return
					}
					if want := fmt.Sprintf("h%d:%s", i, msg); string(got) != want {
						errs <- fmt.Errorf("cross delivery: got %q want %q", got, want)
						return
					}
				}
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestDataTokens(t *testing.T) {
	r := startRelay(t)
	a, b := register(t, r), register(t, r)
	_, evA := connect(t, r, a)
	clientB, evB := connect(t, r, b)

	reject := func(name, endpointID, connectionID, token string, codes ...int) {
		t.Helper()
		_, resp, err := endpoint.Accept(r.base, endpointID, connectionID, token)
		if err == nil {
			t.Fatalf("%s: upgraded", name)
		}
		expectStatus(t, resp, err, codes...)
	}
	reject("wrong token", a.ID, evA.ConnectionID, evB.Token, 403)
	reject("missing token", a.ID, evA.ConnectionID, "", 403)
	reject("truncated token", a.ID, evA.ConnectionID, evA.Token[:20], 403)
	reject("other endpoint pair", a.ID, evB.ConnectionID, evB.Token, 404)
	reject("other endpoint id", b.ID, evA.ConnectionID, evA.Token, 404)
	reject("unknown connection", a.ID, endpoint.B64(randomBytes(16)), evA.Token, 404)
	reject("missing endpoint", "", evA.ConnectionID, evA.Token, 404)

	accept(t, a, evA)
	reject("reused token", a.ID, evA.ConnectionID, evA.Token, 403, 404)

	hostB := accept(t, b, evB)
	msg := message{websocket.TextMessage, []byte("b only")}
	send(t, clientB, msg)
	expectMessage(t, hostB, msg)
}

func TestExpiredToken(t *testing.T) {
	r := startRelay(t, "RELAY_PAIR_TIMEOUT_MS=200")
	h := register(t, r)
	client, ev := connect(t, r, h)
	expectClose(t, client, websocket.CloseTryAgainLater)
	if closed := nextEvent(t, h, "closed"); closed.ConnectionID != ev.ConnectionID {
		t.Fatalf("closed event for wrong pair: %+v", closed)
	}
	_, resp, err := h.Accept(ev)
	expectStatus(t, resp, err, 404)
	r.waitIdle()
}

func TestStaleGenerationCleanup(t *testing.T) {
	r := startRelay(t)
	priv := newKey(t)
	old := registerKey(t, r, priv)
	activeClient, activeHost, _ := pairUp(t, r, old)
	pendingClient, pendingEv := connect(t, r, old)

	old.Control.UnderlyingConn().Close()
	expectClose(t, activeClient, websocket.CloseGoingAway)
	expectClose(t, pendingClient, websocket.CloseGoingAway)
	expectClose(t, activeHost, websocket.CloseGoingAway)
	r.waitMetrics("old host released", func(m map[string]float64) bool {
		return m["activeHosts"] == 0 && m["activePairs"] == 0 && m["pendingPairs"] == 0
	})

	fresh := registerKey(t, r, priv)
	_, resp, err := fresh.Accept(pendingEv)
	expectStatus(t, resp, err, 404)

	client, host, id := pairUp(t, r, fresh)
	activeHost.Close()
	activeClient.Close()
	msg := message{websocket.BinaryMessage, []byte("new generation")}
	send(t, client, msg)
	expectMessage(t, host, msg)

	client.Close()
	if ev := nextEvent(t, fresh, "closed"); ev.ConnectionID != id {
		t.Fatalf("unexpected closed event %+v", ev)
	}
	r.waitMetrics("fresh host intact", func(m map[string]float64) bool {
		return m["activeHosts"] == 1 && m["activePairs"] == 0 && m["pendingPairs"] == 0
	})
	client2, host2, _ := pairUp(t, r, fresh)
	send(t, host2, msg)
	expectMessage(t, client2, msg)
}
