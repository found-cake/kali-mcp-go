package kaliclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostAddsBearerAuthorizationHeader(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("expected bearer token, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"stdout":"ok","stderr":"","return_code":0,"success":true,"timed_out":false}`)
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "secret-token")
	if _, err := client.Post(context.Background(), "/api/tools/nmap", map[string]string{"target": "127.0.0.1"}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestPostUsesProvidedPath(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tools/nmap" {
			t.Fatalf("expected request path /api/tools/nmap, got %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"stdout":"ok","stderr":"","return_code":0,"success":true,"timed_out":false}`)
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "")
	if _, err := client.Post(context.Background(), "/api/tools/nmap", map[string]string{"target": "127.0.0.1"}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestHealthOmitsBearerAuthorizationHeader(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("expected no bearer token on health request, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"healthy","message":"ok","tools_status":{},"all_essential_tools_available":true}`)
	}))
	defer ts.Close()

	client := New(ts.URL, 5*time.Second, "secret-token")
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
