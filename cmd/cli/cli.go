package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	usageMessage string = `Usage:
	zaz seccomp [command] [flags]
`

	errInvalidSyntax error = errors.New("invalid syntax")
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

	code := 1
	if err == errNoSyscallsFound {
		code = 2
	}

	c.exit(code)
}

// Run runs the console application.
func (c *Console) Run(args []string) {
	cmd, err := c.commandFactory(args)
	if err != nil {
		if err == errInvalidSyntax {
			printf(c.stdErr, usageMessage)
		}
		c.exitOnError(c.stdErr, err)
	} else {
		err = cmd.run(c.stdOut)
		if err != nil {
			c.exitOnError(c.stdErr, err)
		}
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

	return nil, errInvalidSyntax
}

func printf(writer io.Writer, format string, args ...interface{}) {
	_, err := writer.Write([]byte(fmt.Sprintf(format, args...)))
	if err != nil {
		panic(err)
	}
}
