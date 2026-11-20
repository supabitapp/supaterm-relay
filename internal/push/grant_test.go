package push

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSealedEndpointsSurviveKeyRotation(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	g := grant{ID: newGrantID(), Platform: "apns", Token: apnsToken, HostKey: []byte{4}, ManagementKey: []byte{4}}
	_, sub := newSealer([][]byte{oldKey}, testOrigin).issue(g, time.Unix(1, 0))

	rotated := newSealer([][]byte{newKey, oldKey}, testOrigin)
	got, ok := rotated.grantAt(sub.Endpoint)
	if !ok || got.ID != g.ID || got.Token != apnsToken || got.ExpiresAt != sub.ExpiresAt {
		t.Fatalf("rotated sealer opened %+v, %v", got, ok)
	}
	_, fresh := rotated.issue(g, time.Unix(1, 0))
	if _, ok := newSealer([][]byte{oldKey}, testOrigin).grantAt(fresh.Endpoint); ok {
		t.Fatal("new endpoints were sealed with the retired key")
	}
	if _, ok := newSealer([][]byte{newKey}, testOrigin).grantAt(sub.Endpoint); ok {
		t.Fatal("an endpoint opened after its key was removed")
	}
}

func TestSealedEndpointsRejectTampering(t *testing.T) {
	s := newSealer([][]byte{bytes.Repeat([]byte{1}, 32)}, testOrigin)
	sealed := s.seal([]byte(`{"g":"x"}`))
	for name, candidate := range map[string]string{
		"flipped byte":  sealed[:20] + flip(sealed[20:]),
		"truncated":     sealed[:len(sealed)-4],
		"other version": "Ag" + sealed[2:],
		"not base64":    sealed + "!",
		"empty":         "",
		"oversized":     strings.Repeat("A", maxEndpointLength+1),
	} {
		if _, ok := s.open(candidate); ok {
			t.Errorf("%s: opened", name)
		}
	}
	if _, ok := s.grantAt("https://other.example" + pushPath + sealed); ok {
		t.Error("opened an endpoint for another origin")
	}
}
