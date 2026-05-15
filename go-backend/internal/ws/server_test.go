package ws

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go-backend/internal/auth"
	"go-backend/internal/store/repo"

	"github.com/gorilla/websocket"
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

	req := httptest.NewRequest(http.MethodGet, "/system-info?type=0&secret="+url.QueryEscape(token), nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for disabled admin token, got %d", rec.Code)
	}
}

func TestServeHTTPRejectsNonAdminToken(t *testing.T) {
	secret := "unit-test-secret"
	token, err := auth.GenerateToken(2, "normal_user", 1, secret)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	server := NewServer(nil, secret)
	server.SetUserAuthStateLookup(func(userID int64) (*auth.UserAuthState, error) {
		return &auth.UserAuthState{ID: userID, RoleID: 1, Status: 1, PasswordChangedAt: 0}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/system-info?type=0&secret="+url.QueryEscape(token), nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for non-admin token, got %d", rec.Code)
	}
}

func TestValidateAdminSessionRejectsAuthStateChanges(t *testing.T) {
	secret := "unit-test-secret"
	token, err := auth.GenerateToken(1, "admin_user", 0, secret)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	claims, err := auth.ParseClaims(token, secret)
	if err != nil {
		t.Fatalf("parse claims: %v", err)
	}

	tests := []struct {
		name  string
		state *auth.UserAuthState
	}{
		{name: "disabled", state: &auth.UserAuthState{ID: 1, RoleID: 0, Status: 0, PasswordChangedAt: 0}},
		{name: "role changed", state: &auth.UserAuthState{ID: 1, RoleID: 1, Status: 1, PasswordChangedAt: 0}},
		{name: "password changed", state: &auth.UserAuthState{ID: 1, RoleID: 0, Status: 1, PasswordChangedAt: claims.IatMs + 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(nil, secret)
			server.SetUserAuthStateLookup(func(userID int64) (*auth.UserAuthState, error) {
				return tt.state, nil
			})

			if ok := server.validateAdminSession(1, claims); ok {
				t.Fatalf("expected session validation to fail for %s state", tt.name)
			}
		})
	}
}

func TestValidateAdminSessionRejectsExpiredToken(t *testing.T) {
	secret := "unit-test-secret"
	token, err := auth.GenerateToken(1, "admin_user", 0, secret)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	claims, err := auth.ParseClaims(token, secret)
	if err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	claims.Exp = 1

	server := NewServer(nil, secret)
	server.SetUserAuthStateLookup(func(userID int64) (*auth.UserAuthState, error) {
		return &auth.UserAuthState{ID: userID, RoleID: 0, Status: 1, PasswordChangedAt: 0}, nil
	})

	if ok := server.validateAdminSession(1, claims); ok {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestServeHTTPAllowsMonitorTokenWithPermission(t *testing.T) {
	secret := "unit-test-secret"
	token, err := auth.GenerateToken(2, "normal_user", 1, secret)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	r, err := repo.Open(t.TempDir() + "/monitor.db")
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	defer r.Close()
	if err := r.InsertMonitorPermission(2, 123); err != nil {
		t.Fatalf("insert permission: %v", err)
	}

	server := NewServer(r, secret)
	server.SetUserAuthStateLookup(func(userID int64) (*auth.UserAuthState, error) {
		return &auth.UserAuthState{ID: userID, RoleID: 1, Status: 1, PasswordChangedAt: 0}, nil
	})

	ts := httptest.NewServer(server)
	defer ts.Close()

	conn, resp, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(ts.URL, "http")+"/system-info?type=0&secret="+url.QueryEscape(token),
		nil,
	)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial websocket error = %v, status=%d", err, resp.StatusCode)
		}
		t.Fatalf("dial websocket error = %v", err)
	}
	_ = conn.Close()
}
