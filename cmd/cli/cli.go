package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	invalidSyntaxMessage string = "invalid syntax "
	usageMessage         string = `Usage:
	zaz seccomp [command] [flags]
`
)

// Console represents a Console application.
type Console struct {
	commandFactory func(args []string) (cliCommand, error)
	stdOut         io.Writer
	stdErr         io.Writer
	exit           func(code int)
}

// NewConsole initialise and return a new Console object.
func NewConsole(stdOut io.Writer, stdErr io.Writer, exit func(int)) *Console {
	if stdOut == (*bytes.Buffer)(nil) {
		panic("stdOut was null")
	}
	if stdErr == (*bytes.Buffer)(nil) {
		panic("stdErr was null")
	}

	return &Console{
		getCommand,
		stdOut,
		stdErr,
		exit,
	}
}

func (c *Console) exitOnError(writer io.Writer, err error) {
	printf(writer, "error: %s\n", err)

	c.exit(1)
}

// Run parses the cli arguments, identify the right command and executes it.
func (c *Console) Run(args []string) {
	cmd, err := getCommand(args)
	if err != nil {
		_, _ = c.stdOut.Write([]byte(usageMessage))
		c.exitOnError(c.stdErr, errors.New(invalidSyntaxMessage))
		return
	}

	err = cmd.run(c.stdOut)
	if err != nil {
		c.exitOnError(c.stdErr, err)
	}
}

type cliCommand interface {
	run(output io.Writer) error
}

func getCommand(args []string) (cliCommand, error) {

	if len(args) >= 2 {
		switch args[1] {
		case "seccomp":
			return newSeccompSubCommand(args[1:])
		}
	}

	return nil, errors.New(invalidSyntaxMessage)
}

func printf(writer io.Writer, format string, args ...interface{}) {
	_, _ = writer.Write([]byte(fmt.Sprintf(format, args...)))
}
