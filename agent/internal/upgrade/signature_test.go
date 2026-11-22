package upgrade

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"incudal-agent/internal/panel"
	"runtime"
	"testing"
)

func TestPackageSignatureBindsVersionArchitectureAndBytes(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("fixture-binary")
	valid := panel.UpgradeInstruction{Version: "v2.0.0", Architecture: runtime.GOARCH}
	valid.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte("payincus/agent-package/v1\n2.0.0\nlinux-"+runtime.GOARCH+"\n"+sha256HexBytes(body))))
	runner := Runner{TrustedPublicKey: public}
	if err := runner.verifyPackageSignature(body, valid); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing", "bytes", "version", "architecture", "key"} {
		instruction, payload, verifier := valid, body, runner
		switch mode {
		case "missing":
			instruction.Signature = ""
		case "bytes":
			payload = []byte("replacement")
		case "version":
			instruction.Version = "v3.0.0"
		case "architecture":
			instruction.Architecture = "unknown"
		case "key":
			verifier.TrustedPublicKey, _, _ = ed25519.GenerateKey(rand.Reader)
		}
		if verifier.verifyPackageSignature(payload, instruction) == nil {
			t.Fatalf("accepted %s", mode)
		}
	}
}
