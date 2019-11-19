package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestMain_Integration(t *testing.T) {
	assertThat := func(assumption string, args []string, expected string) {
		tmpfile, err := ioutil.TempFile("", "fakestdout.*")
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		should := should.New(t)
		var actualErr error
		os.Stdout = tmpfile
		os.Args = args

		main()

		contents, err := ioutil.ReadFile(tmpfile.Name())
		actual := string(contents)

		should.NotError(actualErr, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should return profile for go app simple-app",
		[]string{"zaz", "seccomp", "from-go", "../test/simple-app"},
		`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["sched_yield","futex","write","mmap","exit_group","madvise","rt_sigprocmask","getpid","gettid","tgkill","rt_sigaction","read","getpgrp","arch_prctl"],"action":"SCMP_ACT_ALLOW"}]}`)

	assertThat("should return profile for sample log file",
		[]string{"zaz", "seccomp", "from-log", "--log-file=\"../test/simple-app\"", "21755"},
		`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["futex","openat","nanosleep","epoll_ctl","fstatfs","getdents64","fcntl"],"action":"SCMP_ACT_ALLOW"}]}`)
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
			t.Log("was expecting exit code which did not happen")
			t.FailNow()
		}

		actualOutput := string(output)

		should.BeEqual(expectedErr, e.Error(), assumption)
		should.BeEqual(expectedOutput, actualOutput, assumption)
	}

	assertThat("should exit with code 1 if no args provided", "zaz", "exit status 1", "Usage:\n\tzaz seccomp [command] [flags]\nerror: invalid syntax \n")
}

func TestMain_ErrorCodes_Inception(t *testing.T) {
	args := os.Getenv("ErrorCodes_Args")
	if args != "" {
		os.Args = strings.Split(args, " ")

		main()
	}
}
