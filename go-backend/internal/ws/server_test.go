package ws

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-backend/internal/auth"
)

func TestServeHTTPRejectsDisabledAdminToken(t *testing.T) {
	secret := "unit-test-secret"
	token, err := auth.GenerateToken(1, "admin_user", 0, secret)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	server := NewServer(nil, secret)
	server.SetUserAuthStateLookup(func(userID int64) (*auth.UserAuthState, error) {
		return &auth.UserAuthState{ID: userID, RoleID: 0, Status: 0, PasswordChangedAt: 0}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/system-info?type=0&secret="+token, nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for disabled admin token, got %d", rec.Code)
	}
}
