package seccomp

import (
	"sync"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pjbgf/go-test/should"
)

func TestDockerRunner_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
		return
	}

	var wg sync.WaitGroup
	assertThat := func(assumption, image, cmd string, profile *specs.LinuxSeccomp,
		shouldErr bool) {
		should := should.New(t)
		s, _ := NewDockerRunner(image, cmd)

		err := s.RunWithSeccomp(profile)
		hasErrored := err != nil

		should.BeEqual(shouldErr, hasErrored, assumption)
		wg.Done()
	}

	wg.Add(3)
	go assertThat("should run container with empty profile",
		"alpine",
		"echo hi",
		nil,
		false)
	go assertThat("should run container without command",
		"alpine",
		"",
		nil,
		false)
	go assertThat("should error if profile is too restrictive",
		"alpine",
		"echo hi",
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
		true)

	wg.Wait()
}
