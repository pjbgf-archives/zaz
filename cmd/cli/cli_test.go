package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestNewConsole(t *testing.T) {
	assertThat := func(assumption string, stdOut, stdErr *bytes.Buffer, shouldError bool) {
		should := should.New(t)
		hasErrored := false

		defer func() {
			if r := recover(); r != nil {
				hasErrored = true
			}
		}()

		NewConsole(stdOut, stdErr, func(int) {})

		should.BeEqual(shouldError, hasErrored, assumption)
	}

	var stdOut, stdErr bytes.Buffer
	assertThat("should panic for nil stdOut", nil, &stdErr, true)
	assertThat("should panic for nil stdErr", &stdOut, nil, true)
	assertThat("should not panic if stdErr and stdOut are not nil", &stdOut, &stdErr, false)
}

type commandStub struct {
	hasExecuted bool
	err         error
}

func (c *commandStub) run(output io.Writer) error {
	c.hasExecuted = true
	return c.err
}

func TestRun(t *testing.T) {
	assertThat := func(assumption string, factoryErr, cmdErr error, errored, executedCmd bool) {
		should := should.New(t)
		var (
			hasErrored     bool = false
			stdOut, stdErr bytes.Buffer
		)
		stub := &commandStub{err: cmdErr}
		c := NewConsole(&stdOut, &stdErr, func(code int) { hasErrored = true })
		c.commandFactory = func(args []string) (cliCommand, error) {
			return stub, factoryErr
		}

		c.Run([]string{})

		should.BeEqual(errored, hasErrored, assumption)
		should.BeEqual(executedCmd, stub.hasExecuted, assumption)
	}

	assertThat("should not run command when get error", errors.New("some error"), nil, true, false)
	assertThat("should run command when no errors", nil, nil, false, true)
	assertThat("should handle command errors", nil, errors.New("cmd error"), true, true)
}

func TestCli_GetCommand(t *testing.T) {
	assertThat := func(assumption string, command string, expected interface{}, expectedErr error) {
		should := should.New(t)
		var output bytes.Buffer

		cmdGot, err := getCommand(strings.Split(command, " "))
		outputGot := output.String()
		outputWanted := ""

		should.BeEqual(expectedErr, err, assumption)
		should.BeEqual(outputWanted, outputGot, assumption)
		should.HaveSameType(expected, cmdGot, assumption)
	}

	assertThat("should get 'template' subcommand", "zaz seccomp template web", &seccompTemplate{}, nil)
	assertThat("should get 'brute-force' subcommand", "zaz seccomp docker alpine", &seccompBruteForce{}, nil)
	assertThat("should get 'from-go' subcommand", "zaz seccomp ../../test/simple-app", &seccompFromGo{}, nil)
	assertThat("should get 'from-log' subcommand", "zaz seccomp --log-file=../../test/syslog 123", &seccompFromLog{}, nil)
	assertThat("should error for invalid command", "zaz something", nil, errors.New("invalid syntax"))
}
