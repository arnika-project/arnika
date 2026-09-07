//go:build !linux

package main

import "fmt"

// hardenProcess is a no-op off Linux. darwin is a build-only platform (see
// KEYCONTROL.md, Platform Support), never a deployment target, so there is
// nothing to harden there - but the startup log has to say so rather than let
// the absence of a warning imply the guarantees hold.
func hardenProcess() []error {
	return []error{fmt.Errorf(
		"process hardening (PR_SET_DUMPABLE, RLIMIT_CORE, mlockall) is not implemented on this platform")}
}
