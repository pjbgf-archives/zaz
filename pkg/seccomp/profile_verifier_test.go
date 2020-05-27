package seccomp

import (
	"strings"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestProfileVerifier_Run(t *testing.T) {
	assertThat := func(assumption, profileJson string,
		expectedWarnings []Warning, expectedErr error) {
		should := should.New(t)
		reader := strings.NewReader(profileJson)

		v := NewProfileVerifier(reader)
		actualWarnings, actualErr := v.Run()

		should.BeEqual(expectedErr, actualErr, assumption)
		should.HaveSameItems(expectedWarnings, actualWarnings, assumption)
	}

	assertThat("should error when profile provided is empty",
		``,
		[]Warning{}, ErrInvalidProfile)

	assertThat("should error when profile provided is invalid",
		`some invalid format`,
		[]Warning{}, ErrInvalidProfile)

	assertThat("should error when profile allows high-risk calls",
		`{"syscalls": [
				{"names": ["bpf","add_key","create_module"],"action": "SCMP_ACT_ALLOW"}
			]}`,
		[]Warning{{SyscallName: "bpf"}, {SyscallName: "add_key"}, {SyscallName: "create_module"}},
		ErrHighRiskSyscallAllowed)

	assertThat("should error when profile set high-risk calls on complain mode",
		`{"syscalls": [
					{"names": ["bpf","create_module"],"action": "SCMP_ACT_LOG"}
				]}`,
		[]Warning{{SyscallName: "bpf"}, {SyscallName: "create_module"}},
		ErrHighRiskSyscallAllowed)

	assertThat("should error when profile defaults to complain mode and does not block high-risk calls",
		`{"defaultAction": "SCMP_ACT_LOG"}`,
		[]Warning{{SyscallName: "get_mempolicy"}, {SyscallName: "init_module"}, {SyscallName: "lookup_dcookie"}, {SyscallName: "perf_event_open"}, {SyscallName: "request_key"}, {SyscallName: "swapon"}, {SyscallName: "acct"}, {SyscallName: "delete_module"}, {SyscallName: "mount"}, {SyscallName: "personality"}, {SyscallName: "process_vm_readv"}, {SyscallName: "_sysctl"}, {SyscallName: "userfaultfd"}, {SyscallName: "add_key"}, {SyscallName: "clock_settime"}, {SyscallName: "kexec_file_load"}, {SyscallName: "keyctl"}, {SyscallName: "nfsservctl"}, {SyscallName: "process_vm_writev"}, {SyscallName: "reboot"}, {SyscallName: "stime"}, {SyscallName: "unshare"}, {SyscallName: "clock_adjtime"}, {SyscallName: "iopl"}, {SyscallName: "pivot_root"}, {SyscallName: "quotactl"}, {SyscallName: "vm86old"}, {SyscallName: "kcmp"}, {SyscallName: "ptrace"}, {SyscallName: "query_module"}, {SyscallName: "swapoff"}, {SyscallName: "sysfs"}, {SyscallName: "umount2"}, {SyscallName: "vm86"}, {SyscallName: "create_module"}, {SyscallName: "kexec_load"}, {SyscallName: "mbind"}, {SyscallName: "open_by_handle_at"}, {SyscallName: "set_mempolicy"}, {SyscallName: "setns"}, {SyscallName: "settimeofday"}, {SyscallName: "bpf"}, {SyscallName: "get_kernel_syms"}, {SyscallName: "move_pages"}, {SyscallName: "name_to_handle_at"}, {SyscallName: "umount"}, {SyscallName: "ustat"}, {SyscallName: "finit_module"}, {SyscallName: "ioperm"}, {SyscallName: "uselib"}},
		ErrHighRiskSyscallAllowed)

	assertThat("should error when profile defaults to allow and does not block high-risk calls",
		`{"defaultAction": "SCMP_ACT_ALLOW"}`,
		[]Warning{{SyscallName: "get_mempolicy"}, {SyscallName: "init_module"}, {SyscallName: "lookup_dcookie"}, {SyscallName: "perf_event_open"}, {SyscallName: "request_key"}, {SyscallName: "swapon"}, {SyscallName: "acct"}, {SyscallName: "delete_module"}, {SyscallName: "mount"}, {SyscallName: "personality"}, {SyscallName: "process_vm_readv"}, {SyscallName: "_sysctl"}, {SyscallName: "userfaultfd"}, {SyscallName: "add_key"}, {SyscallName: "clock_settime"}, {SyscallName: "kexec_file_load"}, {SyscallName: "keyctl"}, {SyscallName: "nfsservctl"}, {SyscallName: "process_vm_writev"}, {SyscallName: "reboot"}, {SyscallName: "stime"}, {SyscallName: "unshare"}, {SyscallName: "clock_adjtime"}, {SyscallName: "iopl"}, {SyscallName: "pivot_root"}, {SyscallName: "quotactl"}, {SyscallName: "vm86old"}, {SyscallName: "kcmp"}, {SyscallName: "ptrace"}, {SyscallName: "query_module"}, {SyscallName: "swapoff"}, {SyscallName: "sysfs"}, {SyscallName: "umount2"}, {SyscallName: "vm86"}, {SyscallName: "create_module"}, {SyscallName: "kexec_load"}, {SyscallName: "mbind"}, {SyscallName: "open_by_handle_at"}, {SyscallName: "set_mempolicy"}, {SyscallName: "setns"}, {SyscallName: "settimeofday"}, {SyscallName: "bpf"}, {SyscallName: "get_kernel_syms"}, {SyscallName: "move_pages"}, {SyscallName: "name_to_handle_at"}, {SyscallName: "umount"}, {SyscallName: "ustat"}, {SyscallName: "finit_module"}, {SyscallName: "ioperm"}, {SyscallName: "uselib"}},
		ErrHighRiskSyscallAllowed)

	assertThat("should error when profile defaults to allow and only block some high-risk calls",
		`{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
					{"names": ["get_mempolicy","init_module","lookup_dcookie"],"action": "SCMP_ACT_ERRNO"}
				]}`,
		[]Warning{{SyscallName: "perf_event_open"}, {SyscallName: "request_key"}, {SyscallName: "swapon"}, {SyscallName: "acct"}, {SyscallName: "delete_module"}, {SyscallName: "mount"}, {SyscallName: "personality"}, {SyscallName: "process_vm_readv"}, {SyscallName: "_sysctl"}, {SyscallName: "userfaultfd"}, {SyscallName: "add_key"}, {SyscallName: "clock_settime"}, {SyscallName: "kexec_file_load"}, {SyscallName: "keyctl"}, {SyscallName: "nfsservctl"}, {SyscallName: "process_vm_writev"}, {SyscallName: "reboot"}, {SyscallName: "stime"}, {SyscallName: "unshare"}, {SyscallName: "clock_adjtime"}, {SyscallName: "iopl"}, {SyscallName: "pivot_root"}, {SyscallName: "quotactl"}, {SyscallName: "vm86old"}, {SyscallName: "kcmp"}, {SyscallName: "ptrace"}, {SyscallName: "query_module"}, {SyscallName: "swapoff"}, {SyscallName: "sysfs"}, {SyscallName: "umount2"}, {SyscallName: "vm86"}, {SyscallName: "create_module"}, {SyscallName: "kexec_load"}, {SyscallName: "mbind"}, {SyscallName: "open_by_handle_at"}, {SyscallName: "set_mempolicy"}, {SyscallName: "setns"}, {SyscallName: "settimeofday"}, {SyscallName: "bpf"}, {SyscallName: "get_kernel_syms"}, {SyscallName: "move_pages"}, {SyscallName: "name_to_handle_at"}, {SyscallName: "umount"}, {SyscallName: "ustat"}, {SyscallName: "finit_module"}, {SyscallName: "ioperm"}, {SyscallName: "uselib"}},
		ErrHighRiskSyscallAllowed)

	assertThat("should error when profile defaults to allow and only kill some high-risk calls",
		`{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
						{"names": ["get_mempolicy","init_module","lookup_dcookie"],"action": "SCMP_ACT_KILL"}
					]}`,
		[]Warning{{SyscallName: "perf_event_open"}, {SyscallName: "request_key"}, {SyscallName: "swapon"}, {SyscallName: "acct"}, {SyscallName: "delete_module"}, {SyscallName: "mount"}, {SyscallName: "personality"}, {SyscallName: "process_vm_readv"}, {SyscallName: "_sysctl"}, {SyscallName: "userfaultfd"}, {SyscallName: "add_key"}, {SyscallName: "clock_settime"}, {SyscallName: "kexec_file_load"}, {SyscallName: "keyctl"}, {SyscallName: "nfsservctl"}, {SyscallName: "process_vm_writev"}, {SyscallName: "reboot"}, {SyscallName: "stime"}, {SyscallName: "unshare"}, {SyscallName: "clock_adjtime"}, {SyscallName: "iopl"}, {SyscallName: "pivot_root"}, {SyscallName: "quotactl"}, {SyscallName: "vm86old"}, {SyscallName: "kcmp"}, {SyscallName: "ptrace"}, {SyscallName: "query_module"}, {SyscallName: "swapoff"}, {SyscallName: "sysfs"}, {SyscallName: "umount2"}, {SyscallName: "vm86"}, {SyscallName: "create_module"}, {SyscallName: "kexec_load"}, {SyscallName: "mbind"}, {SyscallName: "open_by_handle_at"}, {SyscallName: "set_mempolicy"}, {SyscallName: "setns"}, {SyscallName: "settimeofday"}, {SyscallName: "bpf"}, {SyscallName: "get_kernel_syms"}, {SyscallName: "move_pages"}, {SyscallName: "name_to_handle_at"}, {SyscallName: "umount"}, {SyscallName: "ustat"}, {SyscallName: "finit_module"}, {SyscallName: "ioperm"}, {SyscallName: "uselib"}},
		ErrHighRiskSyscallAllowed)

	assertThat("should not error when profile blocks high-risk calls",
		`{"syscalls": [
			{"names": ["bpf","add_key","create_module"],"action": "SCMP_ACT_ERRNO"}
		]}`,
		[]Warning{},
		nil)
}
