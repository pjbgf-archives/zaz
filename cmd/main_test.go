package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestMain_Integration(t *testing.T) {
	assertThat := func(assumption string, args []string, expected string) {
		should := should.New(t)
		stdout, err := ioutil.TempFile("", "fakestdout.*")
		if err != nil {
			t.Log("error creating temporary file")
			t.FailNow()
		}
		defer os.Remove(stdout.Name())

		os.Stdout = stdout
		os.Args = args

		main()

		contents, err := ioutil.ReadFile(stdout.Name())
		actual := string(contents)

		should.NotError(err, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should return profile for sample log file",
		[]string{"zaz", "seccomp", "--log-file=\"../test/syslog\"", "21755"},
		`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["epoll_ctl","fcntl","fstatfs","futex","getdents64","nanosleep","openat"],"action":"SCMP_ACT_ALLOW"}]}`)

	assertThat("should return list of high-risk calls from profile",
		[]string{"zaz", "seccomp", "verify", "../test/no-highrisk-profile.json"},
		`[*] No high-risk syscalls found`)

	if !testing.Short() {
		assertThat("should return profile for go app simple-app",
			[]string{"zaz", "seccomp", "../test/simple-app"},
			`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["arch_prctl","close","epoll_ctl","exit_group","fcntl","futex","getpgrp","getpid","gettid","madvise","mmap","read","readlinkat","rt_sigaction","rt_sigprocmask","sched_yield","tgkill","write"],"action":"SCMP_ACT_ALLOW"}]}`)

		assertThat("should brute force echo hi",
			[]string{"zaz", "seccomp", "docker", "alpine", "echo hi"},
			`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["arch_prctl","close","execve","exit","exit_group","futex","mprotect","write"],"action":"SCMP_ACT_ALLOW"}]}`)
	} else {
		t.Skip("skipping tests in short mode.")
	}
}

func TestMain_ErrorCodes(t *testing.T) {
	assertThat := func(assumption, command, expectedErr, expectedOutput string) {
		should := should.New(t)
		exe, _ := os.Executable()

		cmd := exec.Command(exe, "-test.run", "^TestMain_ErrorCodes_Inception$")
		cmd.Env = append(cmd.Env, fmt.Sprintf("ErrorCodes_Args=%s", command))

		output, err := cmd.CombinedOutput()

		e, ok := err.(*exec.ExitError)

		if !ok {
			t.Logf("\nassumption: %s\n  expected: %s\n    actual: exit status 0", assumption, expectedErr)
			t.FailNow()
		}

		actualOutput := string(output)

		should.BeEqual(expectedErr, e.Error(), assumption)
		should.BeEqual(expectedOutput, actualOutput, assumption)
	}

	assertThat("should exit with code 1 if no args provided", "zaz",
		"exit status 1", "Usage:\n\tzaz seccomp [command] [flags]\nerror: invalid syntax\n")

	assertThat("should return error code when empty profile",
		"zaz seccomp --error-when-empty --log-file=\"../test/syslog\" 1",
		"exit status 2", "error: no system calls found\n")

	assertThat("should return error code when invalid template",
		"zaz seccomp template non-existent-template",
		"exit status 1", "error: invalid template name\n")

	assertThat("should return error code when verifying file with high-risk calls",
		"zaz seccomp verify ../test/highrisk-profile.json",
		"exit status 1", "error: profile allows high-risk system calls\n")
}

func TestMain_ErrorCodes_Inception(t *testing.T) {
	args := os.Getenv("ErrorCodes_Args")
	if args != "" {
		os.Args = strings.Split(args, " ")

		main()
	}
}
