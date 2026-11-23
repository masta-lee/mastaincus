package provisioning

import (
	"fmt"
	"regexp"
	"strings"
)

// Early managed hosts used the official HTTP endpoint. Retain their settings,
// but run security transactions against a separate HTTPS-only repository file.
// A custom/tagged/cross-branch source never becomes trusted by normalization.
func reviewedSecurityRepositories(release, original string) (string, error) {
	parts := strings.Split(strings.TrimSpace(release), ".")
	if len(parts) < 2 || !regexp.MustCompile(`^3\.(22|23|24)$`).MatchString(strings.Join(parts[:2], ".")) {
		return "", fmt.Errorf("security package branch unsupported")
	}
	base := "dl-cdn.alpinelinux.org/alpine/v" + strings.Join(parts[:2], ".") + "/"
	seen := map[string]bool{}
	result := []string{}
	for _, line := range strings.Split(original, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path := strings.TrimPrefix(strings.TrimPrefix(line, "https://"), "http://")
		if line != "https://"+path && line != "http://"+path || path != base+"main" && path != base+"community" || seen[path] {
			return "", fmt.Errorf("security package repository needs reviewed update")
		}
		seen[path] = true
		result = append(result, "https://"+path)
	}
	if len(result) == 0 {
		return "", fmt.Errorf("security package repository unavailable")
	}
	return strings.Join(result, "\n") + "\n", nil
}
