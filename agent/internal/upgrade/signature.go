package upgrade

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"

	"incudal-agent/internal/panel"
)

// Independently provisioned publisher identity, shared with signed gateway
// components. Never accept a key from an update response or payload.
const publisherPublicKey = "y6C9aLon6OtgHPp5KPVDpxoNha95YptW03o4Dp2djQA="

func sha256HexBytes(bytes []byte) string { return fmt.Sprintf("%x", sha256.Sum256(bytes)) }

func (runner *Runner) verifyPackageSignature(binary []byte, instruction panel.UpgradeInstruction) error {
	key := runner.TrustedPublicKey
	if len(key) == 0 {
		key, _ = base64.StdEncoding.DecodeString(publisherPublicKey)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(instruction.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("agent package publisher signature invalid")
	}
	if instruction.Architecture != runtime.GOARCH {
		return fmt.Errorf("agent package architecture mismatch")
	}
	version := strings.TrimPrefix(instruction.Version, "v")
	message := []byte("payincus/agent-package/v1\n" + version + "\nlinux-" + instruction.Architecture + "\n" + sha256HexBytes(binary))
	if !ed25519.Verify(key, message, signature) {
		return fmt.Errorf("agent package publisher signature invalid")
	}
	return nil
}
