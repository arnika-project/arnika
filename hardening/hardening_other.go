//go:build !linux

// Package hardening keeps key material out of core dumps, /proc, ptrace and swap.
package hardening

import "fmt"

func Process() []error {
	return []error{fmt.Errorf(
		"process hardening (PR_SET_DUMPABLE, RLIMIT_CORE, mlockall) is not implemented on this platform")}
}
