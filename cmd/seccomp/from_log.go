package seccomp

import (
	"bufio"
	"io"
	"regexp"
	"strconv"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// SyscallsFromLog represents a syscalls source from syslog files.
type SyscallsFromLog struct {
	action     specs.LinuxSeccompAction
	reader     io.Reader
	processIDs []int
}

// NewSyscallsFromLog initialises and returns a new SyscallsFromLog
func NewSyscallsFromLog(reader io.Reader, processIDs []int) *SyscallsFromLog {
	return &SyscallsFromLog{
		specs.ActAllow,
		reader,
		processIDs,
	}
}

// GetSystemCalls returns all system calls found in the syslog for a given processID.
func (s *SyscallsFromLog) GetSystemCalls() (*specs.LinuxSyscall, error) {
	syscalls, err := s.getSystemCallsFromLog()
	if err != nil {
		return nil, err
	}

	if len(syscalls) == 0 {
		return nil, nil
	}

	r := specs.LinuxSyscall{
		Action: s.action,
		Names:  make([]string, 0, len(syscalls)),
	}

	for _, name := range syscalls {
		r.Names = append(r.Names, name)
	}

	return &r, nil
}

func (s *SyscallsFromLog) getSystemCallsFromLog() ([]string, error) {

	scan := bufio.NewScanner(s.reader)
	scan.Split(bufio.ScanLines)

	trackUnique := make(map[int]string)
	syscalls := make([]string, 0)

	for scan.Scan() {
		id := s.extractSyscallID(scan.Text(), s.processIDs)
		if id > -1 {
			if _, ok := trackUnique[id]; !ok {
				trackUnique[id] = ""
				name, err := getSyscallName(id)
				if err != nil {
					return nil, err
				}

				syscalls = append(syscalls, name)
			}
		}
	}

	return syscalls, nil
}

func (*SyscallsFromLog) extractSyscallID(logLine string, processIDs []int) int {
	syscallID := -1

	if logLine == "" || len(processIDs) == 0 || processIDs[0] < 0 {
		return syscallID
	}

	pidRegex := strconv.Itoa(processIDs[0])
	if len(processIDs) > 1 {
		pidRegex = "(" + pidRegex
		for _, pid := range processIDs[1:] {
			pidRegex = pidRegex + "|" + strconv.Itoa(pid)
		}
		pidRegex = pidRegex + ")"
	}

	re := regexp.MustCompile(`(?:audit:.+pid=` + pidRegex + `\b).+syscall=(\b\d+\b)`)
	captures := re.FindStringSubmatch(logLine)

	if captures != nil && len(captures) > 1 {
		if captures[len(captures)-1] != "" {
			if tmpValue, err := strconv.Atoi(captures[len(captures)-1]); err == nil {
				syscallID = tmpValue
			}
		}
	}

	return syscallID
}
