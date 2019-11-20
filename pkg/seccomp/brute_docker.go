package seccomp

import specs "github.com/opencontainers/runtime-spec/specs-go"

type BruteForceSource struct {
}

func NewBruteForceSource() *BruteForceSource {
	return &BruteForceSource{}
}

func (*BruteForceSource) GetSystemCalls() (*specs.LinuxSyscall, error) {
	return &specs.LinuxSyscall{
		Action: specs.ActAllow,
		Names:  []string{"openat", "read", "write", "epoll_pwait", "prctl", "setgid", "futex", "execve", "setgroups", "chdir", "mprotect", "capset", "newfstatat", "setuid", "getdents64", "arch_prctl", "getppid", "close", "fstat", "stat", "fstatfs", "capget"},
	}, nil
}
