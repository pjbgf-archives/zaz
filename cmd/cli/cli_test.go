package cli

import (
	"bytes"
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

func TestCli_InvalidSyntax(t *testing.T) {
	assertThat := func(assumption string, args []string) {
		should := should.New(t)
		var stdOutput, stdError bytes.Buffer
		var hasErrored bool

		c := NewConsole(&stdOutput, &stdError, func(code int) {
			hasErrored = true
		})
		c.Run(args)

		got := stdOutput.String()
		wanted := `Usage:
	zaz seccomp [command] [flags]
`

		should.BeTrue(hasErrored, assumption)
		should.BeEqual(got, wanted, assumption)
	}

	assertThat("should error and print usage for invalid commands", []string{"zaz", "something"})
	assertThat("should error and print usage for not enough arguments", []string{"zaz"})
	assertThat("should error and print usage for empty arguments", []string{})
}

func TestCli_GetCommand(t *testing.T) {
	assertThat := func(assumption string, args []string, expected interface{}) {
		should := should.New(t)
		var output bytes.Buffer

		cmdGot, err := getCommand(args)
		outputGot := output.String()
		outputWanted := ""

		should.NotError(err, assumption)
		should.BeEqual(outputWanted, outputGot, assumption)
		should.HaveSameType(expected, cmdGot, assumption)
	}

	assertThat("should get 'from-go' subcommand", []string{"zaz", "seccomp", "from-go"}, &seccompFromGo{})
	assertThat("should get 'from-log' subcommand", []string{"zaz", "seccomp", "from-log", "123"}, &seccompFromLog{})
}
