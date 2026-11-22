//go:build linux

package provisioning

import "testing"

func TestSecurityPackagePlanRejectsUnrelatedRemovalAndMajorChange(t *testing.T) {
	before := map[string]string{"openssl": "3.5.7-r0", "curl": "8.16.0-r0"}
	if err := safeSecurityPackagePlan("(1/1) Upgrading openssl (3.5.7-r0 -> 3.5.9-r0)", before); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"Removing openssl", "Upgrading openssl (4.0.0-r0)", "Upgrading linux-virt (6.20.1-r0)", "Installing unknown (1.0-r0)", "Downgrading curl (8.0-r0)", "UNTRUSTED"} {
		if safeSecurityPackagePlan(output, before) == nil {
			t.Fatal(output)
		}
	}
}
