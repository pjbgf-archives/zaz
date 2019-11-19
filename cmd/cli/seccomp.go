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
	processSource func(output io.Writer, source seccomp.SyscallsSource) error
	source        seccomp.SyscallsSource
}

// newSeccompFromLog creates a new seccompFromLog command.
func newSeccompFromLog(args []string) (*seccompFromLog, error) {
	processID, syslogPath, err := parseFromLogFlags(args)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(syslogPath)
	if err != nil {
		return nil, fmt.Errorf("syslog file '%s' not found", syslogPath)
	}
	source := seccomp.NewSyscallsFromLog(file, processID)

	return &seccompFromLog{
		processSeccompSource,
		source,
	}, nil
}

func parseFromLogFlags(args []string) (processID int, syslogPath string, err error) {
	if len(args) == 0 {
		err = errors.New(invalidSyntaxMessage)
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
		}
	}

	return
}

func (s *seccompFromLog) run(output io.Writer) error {
	return s.processSource(output, s.source)
}

type seccompFromGo struct {
	processSource func(output io.Writer, source seccomp.SyscallsSource) error
	source        seccomp.SyscallsSource
}

// newSeccompFromGo creates a new seccompFromGo command.
func newSeccompFromGo(args []string) (*seccompFromGo, error) {
	filePath, err := parseFromGoFlags(args)
	if err != nil {
		return nil, err
	}

	return &seccompFromGo{
		processSeccompSource,
		seccomp.NewSyscallsFromGo(filePath)}, nil
}

func parseFromGoFlags(args []string) (filePath string, err error) {
	if len(args) == 0 {
		err = errors.New(invalidSyntaxMessage)
	} else {
		filePath = args[len(args)-1]
	}

	return
}

func (s *seccompFromGo) run(output io.Writer) error {
	return s.processSource(output, s.source)
}

func processSeccompSource(output io.Writer, source seccomp.SyscallsSource) error {
	scmp := seccomp.NewSeccomp(source)
	p, err := scmp.GetProfile()
	if err != nil {
		return err
	}

	json, err := json.Marshal(p)
	if err != nil {
		return err
	}

	_, err = output.Write([]byte(json))
	return err
}

func ifFlag(arg, flagName string) bool {
	f := fmt.Sprintf("--%s=", flagName)
	return strings.HasPrefix(arg, f)
}

func getFlagValue(arg, flagName string) string {
	f := fmt.Sprintf("--%s=", flagName)
	v := strings.TrimPrefix(arg, f)
	return strings.ReplaceAll(v, "\"", "")
}
