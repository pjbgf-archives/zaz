package seccomp

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/zaz/pkg/should"
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
	seccomp := NewSeccomp()
	seccomp.source = newSyscallsSourceStub([]string{"abc", "def"})

	actual, err := seccomp.GetProfile()
	expected := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"abc", "def"}, Action: specs.ActAllow},
		},
	}

	should.NotError(err, "should get profile")
	should.BeEqual(expected, actual, "should get profile")
}
