//go:build !linux

package provisioning

import (
	"context"
	"fmt"
)

func repair(context.Context) error                                        { return fmt.Errorf("Linux host required") }
func ensureDiskSupport(context.Context) error                             { return fmt.Errorf("Linux host required") }
func ensureResourceVisibility(context.Context) error                      { return fmt.Errorf("Linux host required") }
func repairGuestVisibility(context.Context, []Guest) error                { return fmt.Errorf("Linux host required") }
func ResourceMountHelper() (bool, error)                                  { return false, nil }
func incusCompatibilityStatus(context.Context) (string, string, string)   { return "", "", "" }
func prepareIncusCompatibility(context.Context, *CompatPermit) error      { return nil }
func validCompatPermit(*CompatPermit) bool                                { return false }
func reconcileMemoryWatermark(context.Context) error                      { return nil }
func repairSecurityPackages(context.Context) error                        { return nil }
func repairGatewayDNSPythonSecurity(context.Context) error                { return nil }
func migrateLegacyAlpineWorld(context.Context, *LegacyWorldPermit) error  { return nil }
func repairLxcfsSecurity(context.Context, *CompatPermit) error            { return nil }
func repairEmptyHostServiceSecurity(context.Context, *CompatPermit) error { return nil }
func securityLoadedState(context.Context, string) (string, error)         { return "verification-pending", nil }
func localHostMaintenanceEmpty(context.Context) (bool, error) {
	return false, fmt.Errorf("Linux host required")
}
