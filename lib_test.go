package goentitlment

import (
	"testing"
)

func TestAllow(t *testing.T) {
	allowed, err := Allow()
	if err != nil {
		t.Fatalf("Allow() returned error: %v", err)
	}
	if !allowed {
		t.Errorf("Allow() = %v, want true", allowed)
	}
}
