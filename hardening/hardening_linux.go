//go:build linux

// Package hardening keeps key material out of core dumps, /proc, ptrace and swap.
package hardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Process is best effort and returns its failures, because a missing capability must never stop rekeying.
func Process() []error {
	var errs []error

	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		errs = append(errs, fmt.Errorf("PR_SET_DUMPABLE: %w", err))
	}

	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil { // second gate: a piped core_pattern runs its helper as root and ignores PR_SET_DUMPABLE
		errs = append(errs, fmt.Errorf("RLIMIT_CORE: %w", err))
	}

	var memlock unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &memlock); err != nil {
		errs = append(errs, fmt.Errorf("RLIMIT_MEMLOCK read: %w", err))
	} else if memlock.Cur < memlock.Max {
		raised := unix.Rlimit{Cur: memlock.Max, Max: memlock.Max}
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &raised); err != nil {
			errs = append(errs, fmt.Errorf("RLIMIT_MEMLOCK raise: %w", err))
		}
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		errs = append(errs, fmt.Errorf(
			"mlockall: %w - key material may reach swap; grant CAP_IPC_LOCK or set LimitMEMLOCK=infinity, a finite limit is charged against Go's arena reservation and will not suffice",
			err))
	}

	return errs
}
