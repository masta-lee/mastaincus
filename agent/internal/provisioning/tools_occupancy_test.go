package provisioning

import "testing"

func TestEmptyHostMaintenanceRejectsWithheldOccupiedInstructions(t *testing.T) {
	occupied := &CompatPermit{Guests: []CompatGuestPermit{{Name: "original", UUID: "original-uuid", State: "Running"}}}
	if emptyHostServiceCandidate(nil, occupied) {
		t.Fatal("withheld resource list must not start empty-host maintenance for a signed occupied host")
	}
	if emptyHostServiceCandidate([]Guest{{Name: "original"}}, nil) {
		t.Fatal("visible customer must prevent empty-host service maintenance")
	}
	if !emptyHostServiceCandidate(nil, nil) || !emptyHostServiceCandidate(nil, &CompatPermit{}) {
		t.Fatal("empty candidate still needs the existing signed/local empty-host verification")
	}
}
