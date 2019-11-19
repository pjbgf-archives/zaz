package cli

import (
	"bytes"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestCli_InvalidSyntax(t *testing.T) {
	assertThat := func(assumption string, args []string) {
		should := should.New(t)
		var output bytes.Buffer
		var actualErr error

		Run(&output, args, func(err error) {
			actualErr = err
		})

		got := output.String()
		wanted := `Usage:
	zaz seccomp [command] [flags]
`

		should.Error(actualErr, assumption)
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
