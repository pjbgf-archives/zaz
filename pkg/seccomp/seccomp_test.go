package seccomp

import (
	"errors"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/go-test/should"
)

// syscallsSourceStub is a stub of SyscallsSource.
type syscallsSourceStub struct {
	names []string
	err   error
}

func newSyscallsSourceStub(names []string, err error) *syscallsSourceStub {
	return &syscallsSourceStub{names, err}
}

// GetSystemCalls stubs an
func (s *syscallsSourceStub) GetSystemCalls() (*specs.LinuxSyscall, error) {
	return &specs.LinuxSyscall{
		Names:  s.names,
		Action: specs.ActAllow,
	}, s.err
}

func TestGetProfile(t *testing.T) {
	assertThat := func(assumption string, injectedCalls []string,
		expected *specs.LinuxSeccomp, injectedErr, expectedErr error) {
		should := should.New(t)
		source := newSyscallsSourceStub(injectedCalls, injectedErr)
		seccomp := NewSeccomp(source)

		actual, err := seccomp.GetProfile()

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should return nil if no syscalls found", nil, nil, nil, nil)
	assertThat("should error when source errors", nil, nil,
		errors.New("source errored"), errors.New("source errored"))

	assertThat("should get profile when syscalls found",
		[]string{"abc", "def"}, &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Architectures: []specs.Arch{
				specs.ArchX86_64, specs.ArchX86, specs.ArchX32,
			},
			Syscalls: []specs.LinuxSyscall{
				{Names: []string{"abc", "def"}, Action: specs.ActAllow},
			},
		},
		nil, nil)
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
