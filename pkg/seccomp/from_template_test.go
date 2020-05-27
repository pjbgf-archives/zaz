package seccomp

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/go-test/should"
)

func TestGetSystemCalls_FromTemplate(t *testing.T) {
	assertThat := func(assumption string, name ProfileTemplate,
		expected *specs.LinuxSyscall, expectedErr error) {

		should := should.New(t)
		s := NewSyscallsFromTemplate(name)

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

	assertThat("should error for invalid template name", "abcd", nil,
		ErrInvalidTemplateName)

	assertThat("should return profile syscalls for web template", "web",
		&specs.LinuxSyscall{
			Action: specs.ActAllow,
			Names:  webTemplateSyscalls,
		}, nil)
}
