package seccomp

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/zaz/pkg/should"
)

func TestGetSystemCalls_Integration(t *testing.T) {
	should := should.New(t)

	s := NewSyscallsFromGo("../../test/simple-app")
	actual, err := s.GetSystemCalls()

	expected := specs.LinuxSyscall{
		Action: specs.ActAllow,
		Names: []string{
			"sched_yield",
			"futex",
			"write",
			"mmap",
			"exit_group",
			"madvise",
			"rt_sigprocmask",
			"getpid",
			"gettid",
			"tgkill",
			"rt_sigaction",
			"read",
			"getpgrp",
			"arch_prctl",
		},
	}

	should.NotError(err, "should get list of calls with ActAllow")
	should.BeEqual(&expected, actual, "should get list of calls with ActAllow")
}
