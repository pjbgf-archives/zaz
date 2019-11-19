package seccomp

import (
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/go-test/should"
)

func TestGetSystemCalls(t *testing.T) {
	assertThat := func(assumption, log string, processID int, expected *specs.LinuxSyscall, expectedErr error) {
		should := should.New(t)

		reader := strings.NewReader(log)

		s := NewSyscallsFromLog(reader, processID)
		actual, actualErr := s.GetSystemCalls()

		should.BeEqual(expectedErr, actualErr, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should extract syscalls by PID", `
Nov 15 14:34:39 machine kernel: [26233.096391] audit: type=1326 audit(1573828479.772:49): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=15 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=1 compat=0 ip=0x55a02e943be0 code=0x7ffc0000
Nov 15 14:34:39 machine kernel: [26233.096393] audit: type=1326 audit(1573828479.772:50): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=15 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=2 compat=0 ip=0x55a02e943be0 code=0x7ffc0000
`,
		15,
		&specs.LinuxSyscall{
			Action: specs.ActAllow,
			Names: []string{
				"write",
				"open",
			},
		}, nil)

	assertThat("should return empty if can't match by PID", `
	Nov 15 14:34:39 machine kernel: [26233.096391] audit: type=1326 audit(1573828479.772:49): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=15 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=1 compat=0 ip=0x55a02e943be0 code=0x7ffc0000
	Nov 15 14:34:39 machine kernel: [26233.096393] audit: type=1326 audit(1573828479.772:50): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=15 comm="runc:[2:INIT]" exe="/" sig=0 arch=c000003e syscall=2 compat=0 ip=0x55a02e943be0 code=0x7ffc0000
	`,
		20,
		nil, nil)
}
