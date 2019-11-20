package seccomp

import (
	"errors"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/go-test/should"
)

func TestGetSystemCalls_Integration(t *testing.T) {
	assertThat := func(assumption, filePath string,
		expected *specs.LinuxSyscall, expectedErr error) {

		should := should.New(t)
		s := NewSyscallsFromGo(filePath)

		actual, err := s.GetSystemCalls()

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should error for file not found", "../../test/invalid", nil,
		errors.New("could not extract syscalls"))
	assertThat("should get list of calls with ActAllow", "../../test/simple-app",
		&specs.LinuxSyscall{
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
		}, nil)
}
