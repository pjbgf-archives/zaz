package seccomp

import (
	"sort"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Seccomp represents the seccomp profile generation functionatily.
type Seccomp struct {
	defaultAction        specs.LinuxSeccompAction
	targetArchitectures  []string
	source               SyscallsSource
	NilProfileForNoCalls bool
}

// NewSeccomp initialises a new Seccomp.
func NewSeccomp(syscallsSource SyscallsSource) *Seccomp {
	return &Seccomp{
		defaultAction:       specs.ActErrno,
		targetArchitectures: []string{"amd64"},
		source:              syscallsSource,
	}
}

// SyscallsSource defines the interface for syscalls sources.
type SyscallsSource interface {
	GetSystemCalls() (*specs.LinuxSyscall, error)
}

// GetProfile returns a seccomp profile based on the source defined.
func (s *Seccomp) GetProfile() (*specs.LinuxSeccomp, error) {
	syscalls, err := s.source.GetSystemCalls()
	if err != nil {
		return nil, err
	}

	if s.NilProfileForNoCalls {
		if syscalls == nil || len(syscalls.Names) == 0 {
			return nil, nil
		}
	}

	sort.Strings(syscalls.Names)

	arches := getArchitectures(s.targetArchitectures)
	r := specs.LinuxSeccomp{DefaultAction: s.defaultAction,
		Architectures: arches}

	if syscalls != nil {
		r.Syscalls = []specs.LinuxSyscall{*syscalls}
	}
	return &r, nil
}

func getArchitectures(targetArchitectures []string) []specs.Arch {
	arches := make([]specs.Arch, 0, 20)
	for _, arch := range targetArchitectures {
		switch arch {
		case "amd64":
			arches = append(arches, specs.ArchX86_64, specs.ArchX86, specs.ArchX32)
		case "arm64":
			arches = append(arches, specs.ArchARM, specs.ArchAARCH64)
		}
	}

	return arches
}
