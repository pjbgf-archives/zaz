package seccomp

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/should"
)

// syscallsSourceStub is a stub of SyscallsSource.
type syscallsSourceStub struct {
	names []string
}

func newSyscallsSourceStub(names []string) *syscallsSourceStub {
	return &syscallsSourceStub{names}
}

// GetSystemCalls stubs an
func (s *syscallsSourceStub) GetSystemCalls() (specs.LinuxSyscall, error) {
	return specs.LinuxSyscall{
		Names:  s.names,
		Action: specs.ActAllow,
	}, nil
}

func TestGetProfile(t *testing.T) {
	should := should.New(t)
	source := newSyscallsSourceStub([]string{"abc", "def"})
	seccomp := NewSeccomp(source)

	actual, err := seccomp.GetProfile()
	expected := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{
			specs.ArchX86_64, specs.ArchX86, specs.ArchX32,
		},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"abc", "def"}, Action: specs.ActAllow},
		},
	}

	should.NotError(err, "should get profile")
	should.BeEqual(expected, actual, "should get profile")
}

func TestGetArchitectures(t *testing.T) {
	assertThat := func(assumption string, targetArchitectures []string, expected []specs.Arch) {
		should := should.New(t)
		actual := getArchitectures(targetArchitectures)

		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should return empty archs for no target architectures",
		[]string{},
		[]specs.Arch{})
	assertThat("should support amd64",
		[]string{"amd64"},
		[]specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32})
	assertThat("should support arm64",
		[]string{"arm64"},
		[]specs.Arch{specs.ArchARM, specs.ArchAARCH64})
	assertThat("should combine multiple architectures",
		[]string{"amd64", "arm64"},
		[]specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32, specs.ArchARM, specs.ArchAARCH64})
}
