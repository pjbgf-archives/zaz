package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/go-test/should"
	"github.com/pjbgf/zaz/pkg/seccomp"
)

func TestNewSeccompSubCommand(t *testing.T) {
	assertThat := func(assumption string, command string,
		expectedType cliCommand, expectedErr error) {
		should := should.New(t)

		cmd, err := newSeccompSubCommand(strings.Split(command, " "))

		should.BeEqual(expectedErr, err, assumption)
		should.HaveSameType(expectedType, cmd, assumption)
	}

	assertThat("should return seccompFromGo command", "seccomp from-go", &seccompFromGo{}, nil)
	assertThat("should return seccompFromLog command", "seccomp from-log 123", &seccompFromLog{}, nil)
	assertThat("should return error for invalid command", "seccomp blah", nil, errors.New("command not found"))
}

func TestNewSeccompFromLog(t *testing.T) {
	assertThat := func(assumption string, args []string, expected *seccompFromLog, expectedErr error) {
		should := should.New(t)

		actual, err := newSeccompFromLog(args)

		should.BeEqual(expectedErr, err, assumption)
		should.HaveSameType(expected, actual, assumption)
	}

	assertThat("should error for less than one argument", []string{}, nil, errors.New("invalid syntax"))
	assertThat("should error for invalid pid", []string{"abc"}, nil, errors.New("invalid pid"))
	assertThat("should error for syslog file not found", []string{"--log-file=\"/a/a\"", "1"}, nil, errors.New("syslog file '/a/a' not found"))
}

func TestParseFromLogFlags(t *testing.T) {
	assertThat := func(assumption string, args []string, expectedProcessID int,
		expectedSyslogPath string, expectedErr error) {
		should := should.New(t)

		processID, syslogPath, err := parseFromLogFlags(args)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expectedProcessID, processID, assumption)
		should.BeEqual(expectedSyslogPath, syslogPath, assumption)
	}

	assertThat("should use default syslogPath when not set", []string{"1"}, 1, "/var/log/syslog", nil)
	assertThat("should overwrite default syslogPath when it is set", []string{"--log-file=/tmpfile", "2"}, 2, "/tmpfile", nil)
}

func TestSeccompFromLogRun(t *testing.T) {
	assertThat := func(assumption string, command string,
		injectedCalls []string, expected *specs.LinuxSyscall, expectedErr error) {

		should := should.New(t)
		var actual *specs.LinuxSyscall
		cmd, _ := newSeccompFromLog(strings.Split(command, " "))
		cmd.source = newSyscallsSourceStub(injectedCalls, nil)
		cmd.processSource = func(output io.Writer, source seccomp.SyscallsSource) (err error) {
			actual, err = source.GetSystemCalls()
			return
		}

		err := cmd.run(nil)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should get syscalls from syslog file", "12",
		[]string{"abc", "exit"},
		&specs.LinuxSyscall{Names: []string{"abc", "exit"}}, nil)
}

func TestNewSeccompFromGo(t *testing.T) {
	assertThat := func(assumption string, args []string, expected *seccompFromGo, expectedErr error) {
		should := should.New(t)

		actual, err := newSeccompFromGo(args)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should error for less than one argument", []string{},
		nil, errors.New("invalid syntax"))
}

func TestSeccompFromGoRun(t *testing.T) {
	assertThat := func(assumption string, command string,
		injectedCalls []string, expected *specs.LinuxSyscall, expectedErr error) {

		should := should.New(t)
		var actual *specs.LinuxSyscall
		cmd, _ := newSeccompFromGo(strings.Split(command, " "))
		cmd.source = newSyscallsSourceStub(injectedCalls, nil)
		cmd.processSource = func(output io.Writer, source seccomp.SyscallsSource) (err error) {
			actual, err = source.GetSystemCalls()
			return
		}

		err := cmd.run(nil)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should get syscalls from test file", "../../test/simple-app",
		[]string{"abc", "exit"},
		&specs.LinuxSyscall{Names: []string{"abc", "exit"}}, nil)
}

func TestProcessSeccompSource(t *testing.T) {
	assertThat := func(assumption string, injectedCalls []string,
		expected string, injectedErr, expectedErr error) {

		var output bytes.Buffer
		should := should.New(t)
		source := newSyscallsSourceStub(injectedCalls, injectedErr)

		err := processSeccompSource(&output, source)

		actual := output.String()
		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should print call into output", []string{"call1"},
		`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["call1"],"action":""}]}`,
		nil, nil)
	assertThat("should stop if failed to get profile", nil,
		"",
		errors.New("error generating profile"), errors.New("error generating profile"))
}

type syscallsSourceStub struct {
	syscalls []string
	err      error
}

func newSyscallsSourceStub(syscalls []string, err error) *syscallsSourceStub {
	return &syscallsSourceStub{
		syscalls,
		err,
	}
}

// GetSystemCalls returns all system calls injected from newSyscallsSourceStub.
func (s *syscallsSourceStub) GetSystemCalls() (*specs.LinuxSyscall, error) {
	r := specs.LinuxSyscall{
		Names: s.syscalls,
	}

	return &r, s.err
}
