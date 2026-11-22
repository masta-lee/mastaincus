//go:build !linux

package report

// No guessed host filesystem metrics outside the supported Linux host.
func readDiskStats(string) map[string]any { return map[string]any{} }
