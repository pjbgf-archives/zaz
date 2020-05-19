package seccomp

import (
	"errors"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/go-test/should"
)

func TestGetSystemCalls_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping tests in short mode.")
		return
	}

	assertThat := func(assumption, filePath string,
		expected *specs.LinuxSyscall, expectedErr error) {

		should := should.New(t)
		s := NewSyscallsFromGo(filePath)

		actual, err := s.GetSystemCalls()

		should.BeEqual(expectedErr, err, assumption)
		if expected == nil {
			should.BeNil(actual, assumption)
		} else {
			should.BeEqual(expected.Action, actual.Action, assumption)
			should.BeEqual(expected.Args, actual.Args, assumption)
			should.HaveSameItems(expected.Names, actual.Names, assumption)
		}
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
				"epoll_ctl",
				"readlinkat",
				"close",
				"fcntl",
			},
		}, nil)
}
