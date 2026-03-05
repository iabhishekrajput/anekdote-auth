package types_test

import (
	"testing"

	"github.com/iabhishekrajput/anekdote-auth/internal/types"
)

func TestContextKey(t *testing.T) {
	if types.UserContextKey != "user_id" {
		t.Errorf("Expected UserContextKey to be 'user_id', got '%s'", types.UserContextKey)
	}
}
