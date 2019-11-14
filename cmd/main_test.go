package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/pjbgf/zaz/pkg/should"
)

func TestMain_Integration(t *testing.T) {
	assertThat := func(assumption string, args []string, expected string) {
		tmpfile, err := ioutil.TempFile("", "fakestdout.*.zaz")
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		should := should.New(t)
		os.Stdout = tmpfile
		os.Args = args

		main()

		contents, err := ioutil.ReadFile(tmpfile.Name())
		actual := string(contents)

		should.BeEqual(expected, actual, "should return profile for go app")
	}

	assertThat("should return profile for go app",
		[]string{"zaz", "seccomp", "from-go", "test/simple-app"},
		`{ defaultAction = "" }`)
}
