package cli

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"
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

	assertThat("should return seccompFromGo command", "seccomp from-go ../../test/simple-app", &seccompFromGo{}, nil)
	assertThat("should return seccompFromLog command", "seccomp from-log --log-file=../../test/syslog 123", &seccompFromLog{}, nil)
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

	wdSnapshot, _ := os.Getwd()
	// creates tmp folder to make the expected filepath more predictable
	tmpFolder, err := ioutil.TempDir("", "zaz-test")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	os.Chdir(tmpFolder)
	os.Remove(tmpFolder)
	assertThat("should error when refering to a current folder that no longer exists",
		[]string{"--log-file=\"./a\"", "1"}, nil,
		errors.New("error sanitising file name"))

	// returns to previous working directory to ensure other tests' repeatability
	os.Chdir(wdSnapshot)
}

func TestParseFromLogFlags(t *testing.T) {
	assertThat := func(assumption string, args []string, expectedProcessID int,
		expectedSyslogPath string, expectedErrorWhenEmpty bool, expectedErr error) {
		should := should.New(t)

		processID, syslogPath, errorWhenEmpty, err := parseFromLogFlags(args)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expectedProcessID, processID, assumption)
		should.BeEqual(expectedSyslogPath, syslogPath, assumption)
		should.BeEqual(expectedErrorWhenEmpty, errorWhenEmpty, assumption)
	}

	assertThat("should use default syslogPath when not set", []string{"1"}, 1, "/var/log/syslog", false, nil)
	assertThat("should overwrite default syslogPath when it is set", []string{"--log-file=/tmpfile", "2"}, 2, "/tmpfile", false, nil)
	assertThat("should get error-when-empty flag value", []string{"--error-when-empty", "2"}, 2, "/var/log/syslog", true, nil)
}

func TestSeccompFromLogRun(t *testing.T) {
	assertThat := func(assumption string, command string,
		injectedCalls []string, expected *specs.LinuxSyscall, expectedErr error) {

		should := should.New(t)
		var actual *specs.LinuxSyscall
		cmd, _ := newSeccompFromLog(strings.Split(command, " "))
		cmd.source = newSyscallsSourceStub(injectedCalls, nil)
		cmd.processSource = func(output io.Writer, source seccomp.SyscallsSource, errorWhenEmpty bool) (err error) {
			actual, err = source.GetSystemCalls()
			return
		}

		err := cmd.run(nil)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should get syscalls from syslog file", "--log-file=\"../../test/syslog\" 12",
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

	assertThat("should error when less than one argument", []string{},
		nil, errors.New("invalid syntax"))
	assertThat("should error when file not found", []string{"test/simple-app2"},
		nil, errors.New("file 'test/simple-app2' not found"))
}

func TestSeccompFromGoRun(t *testing.T) {
	assertThat := func(assumption string, command string,
		injectedCalls []string, expected *specs.LinuxSyscall, expectedErr error) {

		should := should.New(t)
		var actual *specs.LinuxSyscall
		cmd, _ := newSeccompFromGo(strings.Split(command, " "))
		cmd.source = newSyscallsSourceStub(injectedCalls, nil)
		cmd.processSource = func(output io.Writer, source seccomp.SyscallsSource, errorWhenEmpty bool) (err error) {
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
		expected string, injectedErr, expectedErr error, errWhenEmpty bool) {

		var output bytes.Buffer
		should := should.New(t)
		source := newSyscallsSourceStub(injectedCalls, injectedErr)

		err := processSeccompSource(&output, source, errWhenEmpty)

		actual := output.String()
		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should print call into output", []string{"call1"},
		`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["call1"],"action":""}]}`,
		nil, nil, false)
	assertThat("should stop if failed to get profile", nil,
		"",
		errors.New("error generating profile"), errors.New("error generating profile"),
		false)
	assertThat("should error if no syscalls found and errorWhenEmpty is enabled", nil,
		"",
		nil, errors.New("no system calls found"),
		true)
}

func TestNewBruteForce(t *testing.T) {
	assertThat := func(assumption string, args []string, expected *bruteForce, expectedErr error) {
		should := should.New(t)

		actual, err := newBruteForce(args)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should error when less than two arguments",
		[]string{},
		nil, errors.New("invalid syntax"))
}

func TestParseBruteForceFlags(t *testing.T) {
	assertThat := func(assumption string, args []string,
		expectedType, expectedImg, expectedCmd string, expectedErr error) {
		should := should.New(t)

		runnerType, image, command, err := parseBruteForceFlags(args)

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(expectedType, runnerType, assumption)
		should.BeEqual(expectedImg, image, assumption)
		should.BeEqual(expectedCmd, command, assumption)
	}

	assertThat("should error when image not defined",
		[]string{"brute-force", "docker", "tusyfox", "walk"},
		"docker", "tusyfox", "walk", nil)
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
