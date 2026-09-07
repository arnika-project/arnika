//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// hardenProcess closes the paths by which key material reaches disk or another
// process: core dumps, /proc reads by the same user, ptrace, and swap.
//
// Every step is best effort. A container without CAP_IPC_LOCK, or a seccomp
// profile that filters prctl, must not stop Arnika from rekeying a tunnel, so
// failures are returned for the caller to log rather than being fatal. The
// operator then sees exactly which guarantee is missing.
func hardenProcess() []error {
	var errs []error

	// PR_SET_DUMPABLE 0 suppresses the core dump and, more importantly, makes
	// /proc/<pid>/{mem,environ,maps} root-owned: a process running as the same
	// user can no longer read ARNIKA_PSK or a live PSK out of Arnika's heap,
	// and ptrace attach is refused without CAP_SYS_PTRACE.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		errs = append(errs, fmt.Errorf("PR_SET_DUMPABLE: %w", err))
	}

	// RLIMIT_CORE 0 covers what PR_SET_DUMPABLE does not: a kernel.core_pattern
	// that pipes to a helper runs that helper as root and ignores the dumpable
	// flag, so the limit is the second gate.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		errs = append(errs, fmt.Errorf("RLIMIT_CORE: %w", err))
	}

	// mlockall keeps key material out of swap, which is the one path to disk
	// that SECURITY.md's "no PSK is persisted to disk" claim does not otherwise
	// cover. Raise the soft limit to the hard one first, since a unit file that
	// sets LimitMEMLOCK= only moves the hard limit on some systemd versions.
	//
	// A finite RLIMIT_MEMLOCK does not help: the limit is charged against locked
	// *address space*, and the Go runtime reserves roughly 1.2 GB of heap arena,
	// so mlockall returns ENOMEM for anything short of unlimited. CAP_IPC_LOCK
	// bypasses the limit entirely and is the usual answer. Measured on
	// golang:1.27 in a container: VmLck 1261164 kB with CAP_IPC_LOCK, ENOMEM
	// without it even at a 1 GiB limit.
	//
	// A refused lock is safe rather than merely tolerable: MCL_FUTURE only takes
	// effect once mlockall succeeds, so it cannot leave the process in a state
	// where a later mapping past the limit becomes a fatal out-of-memory.
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
