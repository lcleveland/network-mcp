package change

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestPlanToken(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewStore()
	s.Now = func() time.Time { return now }
	var expired []string
	s.Expired = func(p Plan) { expired = append(expired, p.ID) }
	ok := func(Plan) error { return nil }
	add := func() Plan {
		p, err := s.Add(Plan{Device: "dev1", HostKey: "SHA256:a", Session: "s1"}, ok)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	p := add()
	if b, err := hex.DecodeString(p.ID); err != nil || len(b) != 16 || add().ID == p.ID {
		t.Fatalf("ID %q is not 128 random bits", p.ID)
	}
	if !p.Expires.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("expires %v", p.Expires)
	}
	if _, err := s.Take(p.ID, "s2", "SHA256:a"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("other session: %v", err)
	}
	if _, err := s.Take(p.ID, "s1", "SHA256:b"); err == nil {
		t.Fatal("changed host key accepted")
	}
	if _, err := s.Take(p.ID, "s1", "SHA256:a"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("a refused plan must be gone: %v", err)
	}

	p = add()
	if _, err := s.Take(p.ID, "s1", "SHA256:a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(p.ID, "s1", "SHA256:a"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("reuse: %v", err)
	}

	p = add()
	now = now.Add(10*time.Minute - time.Nanosecond)
	if len(s.Plans()) != 2 {
		t.Fatal("plans before expiry")
	}
	now = now.Add(time.Nanosecond)
	if _, err := s.Take(p.ID, "s1", "SHA256:a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if len(s.Plans()) != 0 || len(expired) != 2 {
		t.Fatalf("expired plans: %v", expired)
	}

	if _, err := s.Add(Plan{}, func(Plan) error { return errors.New("audit down") }); err == nil || len(s.Plans()) != 0 {
		t.Fatal("a plan whose audit failed was stored")
	}
	for range MaxPlans {
		add()
	}
	if _, err := s.Add(Plan{}, ok); err == nil {
		t.Fatal("MaxPlans exceeded")
	}
}
