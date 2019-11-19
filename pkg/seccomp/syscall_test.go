package seccomp

import (
	"errors"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestGetSyscallName(t *testing.T) {
	assertThat := func(assumption string, callID int, expectedName string, expectedErr error) {
		should := should.New(t)

		name, err := getSyscallName(callID)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expectedName, name, assumption)
	}

	assertThat("should get valid system call", 0, "read", nil)
	assertThat("should get error for invalid system call", 777, "", errors.New("syscall id 777 not supported"))
}
