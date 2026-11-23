package panel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"incudal-agent/internal/protocol"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"incudal-agent/internal/abuse"
	"incudal-agent/internal/config"
)

func TestHeartbeatAbusePolicyContract(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		expected       bool
	}{
		{"configured", `{"abusePolicy":{"revision":2,"blockBt":true,"blockMining":false,"retryNonce":4}}`, true},
		{"speed configured", `{"abusePolicy":{"revision":2,"blockBt":true,"blockMining":false,"blockSpeedTest":true,"retryNonce":4}}`, true},
		{"speed null rejected", `{"abusePolicy":{"revision":2,"blockBt":true,"blockMining":false,"blockSpeedTest":null,"retryNonce":4}}`, false},
		{"never configured", `{"abusePolicy":null}`, false},
		{"old server", `{"ok":true}`, false},
		{"partial must not disable", `{"abusePolicy":{"revision":3,"blockBt":false}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != heartbeatPath || r.Header.Get("x-incudal-signature") == "" {
					t.Error("unsigned heartbeat")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				status, ok := body["abusePolicyStatus"].(map[string]any)
				if !ok || status["revision"] != float64(2) || status["retryNonce"] != float64(4) || status["applied"] != true {
					t.Error("status lost on wire", body)
				}
				w.Header().Set("Content-Type", "application/json")
				signTestResponse(w, r, "local-test-fixture", tc.response)
				w.Write([]byte(tc.response))
			}))
			defer server.Close()
			client := New(config.Config{PanelURL: server.URL, AgentID: "local-test", AgentSecret: "local-test-fixture", RequestTimeout: time.Second})
			payload := map[string]any{"abusePolicyStatus": abuse.Status{Instruction: abuse.Instruction{Revision: 2, BlockBT: true, RetryNonce: 4}, Applied: true, CheckedAt: time.Now().UTC().Format(time.RFC3339)}}
			result, err := client.Heartbeat(context.Background(), payload)
			if err != nil || (result.AbusePolicy != nil) != tc.expected {
				t.Fatal(result.AbusePolicy, err)
			}
			if tc.expected && (result.AbusePolicy.Revision != 2 || !result.AbusePolicy.BlockBT || result.AbusePolicy.RetryNonce != 4) {
				t.Fatal(result.AbusePolicy)
			}
			if tc.name == "speed configured" && !result.AbusePolicy.BlockSpeedTest {
				t.Fatal("speed switch lost on wire")
			}
		})
	}
}

func TestPoolHostBBRContract(t *testing.T) {
	for _, tc := range []struct {
		response string
		expected *bool
	}{
		{`{"poolHostBbr":true}`, boolPointer(true)}, {`{"poolHostBbr":false}`, boolPointer(false)}, {`{"ok":true}`, nil}, {`{"poolHostBbr":"true"}`, nil},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signTestResponse(w, r, "local-fixture", tc.response)
			w.Write([]byte(tc.response))
		}))
		client := New(config.Config{PanelURL: server.URL, AgentID: "local-test", AgentSecret: "local-fixture", RequestTimeout: time.Second})
		result, err := client.Heartbeat(context.Background(), map[string]any{})
		server.Close()
		if err != nil || (result.PoolHostBBR == nil) != (tc.expected == nil) {
			t.Fatal(result, err)
		}
		if tc.expected != nil && *result.PoolHostBBR != *tc.expected {
			t.Fatal(result.PoolHostBBR)
		}
	}
}
func boolPointer(value bool) *bool { return &value }
func signTestResponse(w http.ResponseWriter, r *http.Request, secret, body string) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("payincus/agent-response/v1\n" + r.Header.Get("x-incudal-nonce") + "\n"))
	mac.Write([]byte(body))
	w.Header().Set("x-incudal-response-signature", hex.EncodeToString(mac.Sum(nil)))
}

func TestHeartbeatUpgradeResponseAuthentication(t *testing.T) {
	const secret = "isolated-response-authentication-fixture"
	const body = `{"upgrade":{"available":true,"version":"2.0.0","url":"https://fixture.invalid/agent","sha256":"fixture"}}`
	var savedSignature string
	for _, scenario := range []string{"valid", "tampered", "replayed", "missing"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte("payincus/agent-response/v1\n" + r.Header.Get("x-incudal-nonce") + "\n"))
			mac.Write([]byte(body))
			signature := hex.EncodeToString(mac.Sum(nil))
			switch scenario {
			case "valid":
				savedSignature = signature
			case "replayed":
				signature = savedSignature
			case "missing":
				signature = ""
			}
			w.Header().Set("x-incudal-response-signature", signature)
			response := body
			if scenario == "tampered" {
				response = body + " "
			}
			_, _ = w.Write([]byte(response))
		}))
		client := New(config.Config{PanelURL: server.URL, AgentID: "fixture", AgentSecret: secret, RequestTimeout: time.Second})
		result, err := client.Heartbeat(context.Background(), map[string]any{})
		server.Close()
		if err != nil || (result.Upgrade != nil) != (scenario == "valid") {
			t.Fatalf("%s: unexpected update authority: %v %v", scenario, result.Upgrade, err)
		}
	}
}

func TestHeartbeatRejectsRedirectAndOversizedResponse(t *testing.T) {
	for _, scenario := range []string{"redirect", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if scenario == "redirect" {
					w.Header().Set("Location", "/replacement")
					w.WriteHeader(307)
					return
				}
				_, _ = w.Write(make([]byte, 1024*1024+1))
			}))
			defer server.Close()
			client := New(config.Config{PanelURL: server.URL, AgentSecret: "fixture", RequestTimeout: time.Second})
			if _, err := client.Heartbeat(context.Background(), map[string]any{}); err == nil {
				t.Fatal("untrusted response accepted")
			}
			if requests != 1 {
				t.Fatal("redirect was followed")
			}
		})
	}
}

func TestHeartbeatTransientDisconnectRetriesFreshSignedRequests(t *testing.T) {
	for _, first := range []string{"reset", "edge-502"} {
		t.Run(first, func(t *testing.T) {
			calls := 0
			nonces := map[string]bool{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, _ := io.ReadAll(r.Body)
				nonce := r.Header.Get("x-incudal-nonce")
				if nonces[nonce] || nonce == "" {
					t.Error("replayed retry nonce")
				}
				nonces[nonce] = true
				expected := protocol.Signature("retry-fixture", protocol.SigningPayload("POST", heartbeatPath, r.Header.Get("x-incudal-timestamp"), nonce, protocol.BodySHA256(body)))
				if r.Header.Get("x-incudal-signature") != expected {
					t.Error("retry request signature invalid")
				}
				if calls == 1 {
					if first == "edge-502" {
						w.WriteHeader(502)
					} else {
						conn, _, _ := w.(http.Hijacker).Hijack()
						_ = conn.Close()
					}
					return
				}
				const response = `{"poolHostBbr":true}`
				signTestResponse(w, r, "retry-fixture", response)
				_, _ = w.Write([]byte(response))
			}))
			defer server.Close()
			client := New(config.Config{PanelURL: server.URL, AgentSecret: "retry-fixture", RequestTimeout: time.Second})
			result, err := client.Heartbeat(context.Background(), map[string]any{"observed": "unchanged"})
			if err != nil || calls != 2 || result.PoolHostBBR == nil {
				t.Fatalf("retry did not recover: %d %v", calls, err)
			}
		})
	}
}

func TestHeartbeatRetryDoesNotBypassRejectionOrCancellation(t *testing.T) {
	for _, status := range []int{401, 403, 400, 307} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) }))
		client := New(config.Config{PanelURL: server.URL, RequestTimeout: time.Second})
		_, err := client.Heartbeat(context.Background(), map[string]any{})
		server.Close()
		if err == nil || calls != 1 {
			t.Fatalf("status %d retried: %d", status, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(502); cancel() }))
	defer server.Close()
	client := New(config.Config{PanelURL: server.URL, RequestTimeout: time.Second})
	started := time.Now()
	_, err := client.Heartbeat(ctx, map[string]any{})
	if err == nil || calls != 1 || time.Since(started) > time.Second {
		t.Fatal("cancelled retry kept sending")
	}
}

func TestHeartbeatRetryIsFiniteAndRejectsTLSIdentityFailure(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	client := New(config.Config{PanelURL: server.URL, RequestTimeout: time.Second})
	started := time.Now()
	_, err := client.Heartbeat(context.Background(), map[string]any{})
	server.Close()
	if err == nil || calls != 3 || time.Since(started) > 5*time.Second {
		t.Fatalf("unbounded retry: %d %v", calls, err)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached application") }))
	defer tlsServer.Close()
	client = New(config.Config{PanelURL: tlsServer.URL, RequestTimeout: time.Second})
	started = time.Now()
	_, err = client.Heartbeat(context.Background(), map[string]any{})
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("TLS identity failure retried or accepted")
	}
}
