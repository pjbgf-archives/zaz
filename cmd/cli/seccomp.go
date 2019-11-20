package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pjbgf/zaz/pkg/seccomp"
)

func newSeccompSubCommand(args []string) (cliCommand, error) {

	if len(args) > 1 {
		switch args[1] {
		case "from-go":
			return newSeccompFromGo(args[1:])
		case "from-log":
			return newSeccompFromLog(args[1:])
		}
	}

	return nil, errors.New("command not found")
}

type seccompFromLog struct {
	processSource  func(io.Writer, seccomp.SyscallsSource, bool) error
	source         seccomp.SyscallsSource
	errorWhenEmpty bool
}

// newSeccompFromLog creates a new seccompFromLog command.
func newSeccompFromLog(args []string) (*seccompFromLog, error) {
	processID, syslogPath, errorWhenEmpty, err := parseFromLogFlags(args)
	if err != nil {
		return nil, err
	}

	filePath, err := sanitiseFileName(syslogPath)
	if err != nil {
		return nil, errors.New("error sanitising file name")
	}

	/* #nosec file path has been sanitised */
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("syslog file '%s' not found", syslogPath)
	}

	source := seccomp.NewSyscallsFromLog(file, processID)

	return &seccompFromLog{
		processSeccompSource,
		source,
		errorWhenEmpty,
	}, nil
}

func parseFromLogFlags(args []string) (processID int, syslogPath string, errorWhenEmpty bool, err error) {
	if len(args) == 0 {
		err = errInvalidSyntax
	} else {
		processID, err = strconv.Atoi(args[len(args)-1])
		if err != nil {
			err = errors.New("invalid pid")
		}

		syslogPath = "/var/log/syslog"
		for _, arg := range args[:len(args)-1] {
			if ifFlag(arg, "log-file") {
				syslogPath = getFlagValue(arg, "log-file")
			}
			if ifFlag(arg, "error-when-empty") {
				errorWhenEmpty = true
			}
		}
	}

	return
}

func (s *seccompFromLog) run(output io.Writer) error {
	return s.processSource(output, s.source, s.errorWhenEmpty)
}

type seccompFromGo struct {
	processSource  func(io.Writer, seccomp.SyscallsSource, bool) error
	source         seccomp.SyscallsSource
	errorWhenEmpty bool
}

// newSeccompFromGo creates a new seccompFromGo command.
func newSeccompFromGo(args []string) (*seccompFromGo, error) {
	inputPath, errorWhenEmpty, err := parseFromGoFlags(args)
	if err != nil {
		return nil, err
	}

	filePath, err := sanitiseFileName(inputPath)
	if err != nil {
		return nil, errors.New("error sanitising file name")
	}

	if !fileExists(filePath) {
		return nil, fmt.Errorf("file '%s' not found", inputPath)
	}

	return &seccompFromGo{
		processSeccompSource,
		seccomp.NewSyscallsFromGo(filePath),
		errorWhenEmpty}, nil
}

func parseFromGoFlags(args []string) (filePath string, errorWhenEmpty bool, err error) {
	if len(args) == 0 {
		err = errInvalidSyntax
	} else {
		filePath = args[len(args)-1]
		for _, arg := range args[:len(args)-1] {
			if ifFlag(arg, "error-when-empty") {
				errorWhenEmpty = true
			}
		}
	}

	return
}

func (s *seccompFromGo) run(output io.Writer) error {
	return s.processSource(output, s.source, s.errorWhenEmpty)
}

func processSeccompSource(output io.Writer, source seccomp.SyscallsSource, errorWhenEmpty bool) error {
	scmp := seccomp.NewSeccomp(source)
	scmp.NilProfileForNoCalls = errorWhenEmpty
	p, err := scmp.GetProfile()
	if err != nil {
		return err
	}
	if errorWhenEmpty && p == nil {
		printf(output, "error: no system calls found\n")
		os.Exit(2)
	}

	json, err := json.Marshal(p)
	if err != nil {
		return err
	}

	_, err = output.Write([]byte(json))
	return err
}

func ifFlag(arg, flagName string) bool {
	f := fmt.Sprintf("--%s", flagName)
	return strings.HasPrefix(arg, f)
}

func getFlagValue(arg, flagName string) string {
	f := fmt.Sprintf("--%s=", flagName)
	v := strings.TrimPrefix(arg, f)
	return strings.ReplaceAll(v, "\"", "")
}
