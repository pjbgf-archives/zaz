package seccomp

import (
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// BruteForceSource represents a system calls source based on a brute force approach.
type BruteForceSource struct {
	options []string
	runner  BruteForceRunner
}

// BruteForceRunner defines the interface for brute force runners.
type BruteForceRunner interface {
	RunWithSeccomp(profile *specs.LinuxSeccomp) error
}

// NewBruteForceSource initialises BruteForceSource.
func NewBruteForceSource(runner BruteForceRunner) *BruteForceSource {
	s := getMostFrequentSyscalls()
	return &BruteForceSource{
		runner:  runner,
		options: s,
	}
}

func isEssentialCall(syscall string) bool {
	switch syscall {
	case "close", "exit", "execve", "exit_group", "futex":
		return true
	}
	return false
}

func (s *BruteForceSource) canRunBlockingSyscall(syscall string) bool {
	if isEssentialCall(syscall) {
		return false
	}

	tmpSyscalls := s.excludeItemFromSlice(s.options, syscall)
	err := s.runner.RunWithSeccomp(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: tmpSyscalls, Action: specs.ActAllow},
		},
	})
	return err == nil
}

// GetSystemCalls returns all system calls found by brute forcing the profile using a runner.
func (s *BruteForceSource) GetSystemCalls() (*specs.LinuxSyscall, error) {
	mustHaves := make([]string, 0, 60)

	if err := s.runner.RunWithSeccomp(nil); err != nil {
		return nil, fmt.Errorf("execution aborted, command could not be executed: %v", err)
	}

	process := func(scs []string) []string {
		items := make([]string, 0, 60)
		for _, syscall := range scs {
			if !s.canRunBlockingSyscall(syscall) {
				items = append(items, syscall)
			}
		}
		return items
	}

	mustHaves = append(mustHaves, process(s.options)...)

	return &specs.LinuxSyscall{
		Action: specs.ActAllow,
		Names:  mustHaves,
	}, nil
}

func (s *BruteForceSource) indexesOf(source []string, item string) []int {
	indexes := make([]int, 0, len(source))
	for i, currentItem := range source {
		if currentItem == item {
			indexes = append(indexes, i)
		}
	}

	return indexes
}

func (s *BruteForceSource) excludeItemFromSlice(source []string, itemToExclude string) []string {
	indexes := s.indexesOf(source, itemToExclude)
	if len(indexes) == 0 {
		return source
	}

	newSlice := make([]string, 0, len(source))
	nextFirstIndex := 0
	for _, i := range indexes {
		newSlice = append(newSlice, source[nextFirstIndex:i]...)
		nextFirstIndex = i + 1
	}

	newSlice = append(newSlice, source[nextFirstIndex:]...)
	return newSlice
}
