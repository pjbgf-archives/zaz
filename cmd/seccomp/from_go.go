package seccomp

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/gosystract/cmd/systract"
)

// SyscallsFromGo represents a syscalls source from go executables.
type SyscallsFromGo struct {
	filePath string
	action   specs.LinuxSeccompAction
}

// NewSyscallsFromGo initialises and returns a new syscallsFromGo
func NewSyscallsFromGo(filePath string) *SyscallsFromGo {
	return &SyscallsFromGo{
		filePath: filePath,
		action:   specs.ActAllow,
	}
}

// GetSystemCalls returns all system calls found in the go executable specified at filePath.
func (s *SyscallsFromGo) GetSystemCalls() (specs.LinuxSyscall, error) {
	source := systract.NewExeReader(s.filePath)
	syscalls, err := systract.Extract(source)
	if err != nil {
		return specs.LinuxSyscall{}, err
	}

	r := specs.LinuxSyscall{
		Action: s.action,
		Names:  make([]string, 0, len(syscalls)),
	}

	for _, syscall := range syscalls {
		r.Names = append(r.Names, syscall.Name)
	}

	return r, nil
}
