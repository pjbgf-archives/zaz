package seccomp

import specs "github.com/opencontainers/runtime-spec/specs-go"

// Seccomp represents the seccomp profile generation functionatily.
type Seccomp struct {
	defaultAction specs.LinuxSeccompAction
	source        SyscallsSource
}

// NewSeccomp initialises a new Seccomp.
func NewSeccomp() *Seccomp {
	return &Seccomp{
		defaultAction: specs.ActErrno,
	}
}

// SyscallsSource defines the interface for syscalls sources.
type SyscallsSource interface {
	GetSystemCalls() (specs.LinuxSyscall, error)
}

// GetProfile returns a seccomp profile based on the source defined.
func (s *Seccomp) GetProfile() (*specs.LinuxSeccomp, error) {
	syscalls, err := s.source.GetSystemCalls()
	if err != nil {
		return nil, err
	}

	return &specs.LinuxSeccomp{
		DefaultAction: s.defaultAction,
		Syscalls:      []specs.LinuxSyscall{syscalls},
	}, nil
}
