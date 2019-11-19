package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestMain_Integration(t *testing.T) {
	assertThat := func(assumption string, args []string, expected string) {
		tmpfile, err := ioutil.TempFile("", "fakestdout.*.zaz")
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		should := should.New(t)
		var actualErr error
		os.Stdout = tmpfile
		os.Args = args

		onError = func(err error) {
			actualErr = err
		}

		main()

		contents, err := ioutil.ReadFile(tmpfile.Name())
		actual := string(contents)

		should.NotError(actualErr, assumption)
		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should return profile for go app simple-app",
		[]string{"zaz", "seccomp", "from-go", "../test/simple-app"},
		`{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["sched_yield","futex","write","mmap","exit_group","madvise","rt_sigprocmask","getpid","gettid","tgkill","rt_sigaction","read","getpgrp","arch_prctl"],"action":"SCMP_ACT_ALLOW"}]}`)

}
