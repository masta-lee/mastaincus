//go:build linux

package localincus

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQueryUsesOnlyBoundedLocalGET(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	response := `{"type":"sync","status_code":200,"metadata":[]}`
	status := 200
	var mu sync.Mutex
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("mutation reached local API")
		}
		if r.URL.Path == "/1.0/stall" {
			<-r.Context().Done()
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if status == 302 {
			w.Header().Set("Location", "https://outside.invalid/1.0")
		}
		w.WriteHeader(status)
		fmt.Fprint(w, response)
	})}
	go server.Serve(listener)
	defer server.Close()
	data, err := querySocket(context.Background(), path, "/1.0/instances?recursion=1", false)
	if err != nil || string(data) != "[]" {
		t.Fatal("native metadata", string(data), err)
	}
	for _, invalid := range []string{"https://outside/1.0", "//outside/1.0", "/1.0/../secrets", "/1.0\n"} {
		if _, err := querySocket(context.Background(), path, invalid, true); err == nil {
			t.Fatal("query scope escaped", invalid)
		}
	}
	mu.Lock()
	response = `{"type":"sync","status_code":200,"metadata":{}}`
	mu.Unlock()
	if data, err = querySocket(context.Background(), path, "/1.0/operations?recursion=1", false); err != nil || len(data) != 0 {
		t.Fatal("CLI empty convention")
	}
	if data, err = querySocket(context.Background(), path, "/1.0/operations?recursion=1", true); err != nil || string(data) != response {
		t.Fatal("raw proof lost")
	}
	if data, err = querySocket(context.Background(), path, "/internal/ready", true); err != nil || string(data) != response {
		t.Fatal("internal readiness proof lost")
	}
	if _, err = querySocket(context.Background(), path, "/internal/other", true); err == nil {
		t.Fatal("unrelated internal query accepted")
	}
	for _, bad := range []string{`{}`, `{"type":"error","status_code":200,"metadata":[]}`, `{"type":"sync","status_code":500,"metadata":[]}`, `{"type":"sync","status_code":200}`, `{"type":"sync","status_code":200,"metadata":null}`, strings.Repeat("x", MaxResponseBytes+1)} {
		mu.Lock()
		response = bad
		mu.Unlock()
		if _, err := querySocket(context.Background(), path, "/1.0", false); err == nil {
			t.Fatal("unconfirmed metadata accepted")
		}
	}
	mu.Lock()
	status = 302
	mu.Unlock()
	if _, err := querySocket(context.Background(), path, "/1.0", false); err == nil {
		t.Fatal("redirect accepted")
	}
	mu.Lock()
	status = 200
	mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := querySocket(ctx, path, "/1.0/stall", false); err == nil || time.Since(started) > time.Second {
		t.Fatal("query deadline ignored")
	}
}
