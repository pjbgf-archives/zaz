package cli

import (
	"bytes"
	"testing"

	"github.com/pjbgf/zaz/pkg/should"
)

func TestCli_InvalidSyntax(t *testing.T) {
	assertThat := func(assumption string, args []string) {
		should := should.New(t)
		var output bytes.Buffer

		err := Run(&output, args)
		got := output.String()
		wanted := `Usage:
	zaz seccomp [command] [flags]
`

		should.Error(err, assumption)
		should.BeEqual(got, wanted, assumption)
	}

	assertThat("should error and print usage for invalid commands", []string{"zaz", "something"})
	assertThat("should error and print usage for not enough arguments", []string{"zaz"})
	assertThat("should error and print usage for empty arguments", []string{})
}

func TestCli_GetCommand(t *testing.T) {
	assertThat := func(assumption string, args []string) {
		should := should.New(t)
		var output bytes.Buffer

		cmdGot, err := getCommand(args)
		outputGot := output.String()
		outputWanted := ""
		cmdWanted, _ := newSeccompFromGo(args)

		should.NotError(err, assumption)
		should.BeEqual(outputGot, outputWanted, assumption)
		should.HaveSameType(cmdGot, cmdWanted, assumption)
	}

	assertThat("should get 'from-go' subcommand", []string{"zaz", "seccomp", "from-go"})
}

func TestCli_FromGo_Integration(t *testing.T) {
	t.Run("should return profile for go app", func(t *testing.T) {
		should := should.New(t)
		args := []string{"zaz", "seccomp", "from-go", "test/simple-app"}
		var output bytes.Buffer

		err := Run(&output, args)
		got := output.String()
		wanted := `{ defaultAction = "" }`

		should.NotError(err, "should return profile for go app")
		should.BeEqual(wanted, got, "should return profile for go app")
	})
}
