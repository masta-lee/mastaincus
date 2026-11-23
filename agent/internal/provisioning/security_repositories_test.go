package provisioning

import "testing"

func TestSecurityRepositoriesRetainLegacySettingsWithIndependentHTTPS(t *testing.T) {
	for _, version := range []string{"3.22.3", "3.23.0", "3.24.4"} {
		branch := version[:4]
		base := "dl-cdn.alpinelinux.org/alpine/v" + branch + "/"
		for _, protocol := range []string{"http://", "https://"} {
			input := "# owner configuration\n" + protocol + base + "main\n" + protocol + base + "community\n"
			output, err := reviewedSecurityRepositories(version, input)
			if err != nil || output != "https://"+base+"main\nhttps://"+base+"community\n" {
				t.Fatal("original official endpoint was not upgraded for the transaction", output, err)
			}
		}
	}
	for _, source := range []string{"", "# empty\n", "https://dl-cdn.alpinelinux.org/alpine/edge/main", "https://dl-cdn.alpinelinux.org/alpine/v3.23/main", "http://example.com/alpine/v3.24/main", "@custom https://dl-cdn.alpinelinux.org/alpine/v3.24/main", "https://dl-cdn.alpinelinux.org/alpine/v3.24/main?untrusted=1", "dl-cdn.alpinelinux.org/alpine/v3.24/main", "https://dl-cdn.alpinelinux.org/alpine/v3.24/main\nhttp://dl-cdn.alpinelinux.org/alpine/v3.24/main"} {
		if _, err := reviewedSecurityRepositories("3.24.4", source); err == nil {
			t.Fatal("unreviewed or ambiguous source accepted", source)
		}
	}
	if _, err := reviewedSecurityRepositories("3.21.0", "https://dl-cdn.alpinelinux.org/alpine/v3.21/main"); err == nil {
		t.Fatal("unsupported branch accepted")
	}
}
