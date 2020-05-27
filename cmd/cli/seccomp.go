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

var (
	seccompUsageMessage string = `Usage:
	zaz seccomp docker IMAGE [COMMAND]
	zaz seccomp verify SECCOMP-PROFILE-PATH
	zaz seccomp template TEMPLATE-NAME
	zaz seccomp GO-BINARY
	zaz seccomp --log-file=SYSLOG-PATH PID
`

	defaultSysLogPath  string = "/var/log/syslog"
	errNoSyscallsFound error  = errors.New("no system calls found")
)

func newSeccompSubCommand(args []string) (cliCommand, error) {

	if len(args) > 1 {
		switch args[1] {
		case "docker":
			return newSeccompBruteForce(args[1:])
		case "verify":
			return newSeccompVerify(args[1:])
		case "template":
			return newSeccompTemplate(args[1:])
		default:
			lastArg := args[len(args)-1:]
			if _, err := strconv.Atoi(lastArg[0]); err == nil {
				return newSeccompFromLog(args[1:])
			} else if _, err := os.Stat(lastArg[0]); err == nil {
				return newSeccompFromGo(args[1:])
			}
		}
	}

	return &seccompUsage{}, nil
}

type seccompUsage struct{}

func (s *seccompUsage) run(output io.Writer) error {
	/* #nosec */
	_, _ = output.Write([]byte(seccompUsageMessage))
	return nil
}

type seccompFromLog struct {
	processSource  func(io.Writer, seccomp.SyscallsSource, bool) error
	source         seccomp.SyscallsSource
	errorWhenEmpty bool
}

// newSeccompVerify creates a new seccompVerify command.
func newSeccompVerify(args []string) (*seccompVerify, error) {
	profilePath, err := parseVerifyFlags(args)
	if err != nil {
		return nil, err
	}

	filePath, err := sanitiseFileName(profilePath)
	if err != nil {
		return nil, errors.New("error sanitising file name")
	}

	/* #nosec file path has been sanitised */
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("profile file '%s' not found", filePath)
	}

	return &seccompVerify{
		file,
	}, nil
}

func parseVerifyFlags(args []string) (string, error) {
	if len(args) == 0 {
		return "", errInvalidSyntax
	}
	return args[len(args)-1], nil
}

type seccompVerify struct {
	profileReader io.Reader
}

func (s *seccompVerify) run(output io.Writer) error {
	verifier := seccomp.NewProfileVerifier(s.profileReader)
	warnings, err := verifier.Run()
	if err != nil {
		return err
	}
	if len(warnings) > 0 {
		/* #nosec */
		_, _ = output.Write([]byte("[!] Verification failed!\n\nHigh risk syscalls being allowed:\n"))
		for _, warn := range warnings {
			/* #nosec */
			_, _ = output.Write([]byte(fmt.Sprintln(warn.SyscallName)))
		}
	} else {
		/* #nosec */
		_, _ = output.Write([]byte("[*] No high-risk syscalls found"))
	}

	return nil
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

		syslogPath = defaultSysLogPath
		for _, arg := range args[:len(args)-1] {
			if isFlag(arg, "log-file") {
				syslogPath = getFlagValue(arg, "log-file")
			}
			if isFlag(arg, "error-when-empty") {
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
			if isFlag(arg, "error-when-empty") {
				errorWhenEmpty = true
			}
		}
	}

	return
}

func (s *seccompFromGo) run(output io.Writer) error {
	return s.processSource(output, s.source, s.errorWhenEmpty)
}

type seccompBruteForce struct {
	processSource  func(io.Writer, seccomp.SyscallsSource, bool) error
	source         seccomp.SyscallsSource
	errorWhenEmpty bool
}

func newSeccompBruteForce(args []string) (*seccompBruteForce, error) {
	image, command, err := parseBruteForceFlags(args)
	if err != nil {
		return &seccompBruteForce{}, err
	}

	var runner seccomp.BruteForceRunner
	runner, err = seccomp.NewDockerRunner(image, command)
	if err != nil {
		return nil, err
	}

	return &seccompBruteForce{
		processSeccompSource,
		seccomp.NewBruteForceSource(runner),
		true}, nil
}

func parseBruteForceFlags(args []string) (image, command string, err error) {
	if len(args) < 2 {
		err = errInvalidSyntax
		return
	}
	image = args[1]

	if len(args) > 2 {
		command = args[2]
	}

	return
}

func (s *seccompBruteForce) run(output io.Writer) error {
	return s.processSource(output, s.source, s.errorWhenEmpty)
}

type seccompTemplate struct {
	name string
}

func newSeccompTemplate(args []string) (*seccompTemplate, error) {
	name, err := parseTemplateFlags(args)
	if err != nil {
		return nil, err
	}

	return &seccompTemplate{name}, nil
}

func (s *seccompTemplate) run(output io.Writer) error {
	var templateName seccomp.ProfileTemplate
	if s.name == "web" {
		templateName = seccomp.WebTemplate
	}
	templateName = seccomp.ProfileTemplate(s.name)

	source := seccomp.NewSyscallsFromTemplate(templateName)
	return processSeccompSource(output, source, false)
}

func parseTemplateFlags(args []string) (name string, err error) {
	if len(args) != 2 {
		err = errInvalidSyntax
		return
	}
	name = args[1]
	return
}

func processSeccompSource(output io.Writer, source seccomp.SyscallsSource, errorWhenEmpty bool) error {
	scmp := seccomp.NewSeccomp(source)
	scmp.NilProfileForNoCalls = errorWhenEmpty
	p, err := scmp.GetProfile()
	if err != nil {
		return err
	}
	if errorWhenEmpty && p == nil {
		return errNoSyscallsFound
	}

	json, err := json.Marshal(p)
	if err != nil {
		return err
	}

	_, err = output.Write([]byte(json))
	return err
}

func isFlag(arg, flagName string) bool {
	f := fmt.Sprintf("--%s", flagName)
	return strings.HasPrefix(arg, f)
}

func getFlagValue(arg, flagName string) string {
	f := fmt.Sprintf("--%s=", flagName)
	v := strings.TrimPrefix(arg, f)
	return strings.ReplaceAll(v, "\"", "")
}
