package seccomp

import specs "github.com/opencontainers/runtime-spec/specs-go"

type BruteForceSource struct {
	options []string
	runner  BruteForceRunner
}

type BruteForceRunner interface {
	Run(profile *specs.LinuxSeccomp)
	HasExecuted() bool
}

type DockerRunner struct {
}

func NewDockerRunner() *DockerRunner {
	return &DockerRunner{}
}

func (r *DockerRunner) Run(profile *specs.LinuxSeccomp) {

}

func (r *DockerRunner) HasExecuted() bool {
	return false
}

func NewBruteForceSource(runner BruteForceRunner) *BruteForceSource {
	return &BruteForceSource{
		runner:  runner,
		options: []string{"openat", "read", "write", "epoll_pwait", "prctl", "setgid", "futex", "execve", "setgroups", "chdir", "mprotect", "capset", "newfstatat", "setuid", "getdents64", "arch_prctl", "getppid", "close", "fstat", "stat", "fstatfs", "capget"}}
}

func (s *BruteForceSource) GetSystemCalls() (*specs.LinuxSyscall, error) {
	mustHaves := make([]string, 0, 50)
	for _, syscall := range s.options {
		tmpSyscalls := s.excludeItemFromSlice(s.options, syscall)
		s.runner.Run(&specs.LinuxSeccomp{Syscalls: []specs.LinuxSyscall{
			specs.LinuxSyscall{Names: tmpSyscalls},
		}})

		if !s.runner.HasExecuted() {
			mustHaves = append(mustHaves, syscall)
		}
	}

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
