package seccomp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type BruteForceSource struct {
	options []string
	runner  BruteForceRunner
}

type BruteForceRunner interface {
	RunWithSeccomp(profile *specs.LinuxSeccomp) error
}

type DockerRunner struct {
	Image   string
	Command string
}

func NewDockerRunner(img, cmd string) *DockerRunner {
	return &DockerRunner{
		Image:   img,
		Command: cmd,
	}
}

// RunWithSeccomp creates a container and runs the defined command.
func (r *DockerRunner) RunWithSeccomp(profile *specs.LinuxSeccomp) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	_, err = cli.ImagePull(ctx, r.Image, types.ImagePullOptions{})
	if err != nil {
		return err
	}

	hostCfg := container.HostConfig{
		SecurityOpt: []string{"no-new-privileges"},
	}
	cfg := container.Config{
		Image: r.Image,
		Cmd:   strings.Fields(r.Command),
		Tty:   false,
	}

	if profile != nil {
		content, _ := json.Marshal(profile)
		hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "seccomp="+string(content))
	}

	resp, err := cli.ContainerCreate(ctx, &cfg, &hostCfg, nil, "")
	if err != nil {
		return err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case <-statusCh:
	}

	status, err := cli.ContainerInspect(ctx, resp.ID)
	if err != nil {
		return err
	}

	if !status.State.Running && status.State.ExitCode != 0 {
		return errors.New("errored on execution")
	}

	return nil
}

func NewBruteForceSource(runner BruteForceRunner) *BruteForceSource {
	s := getAllSyscallNames()
	return &BruteForceSource{
		runner:  runner,
		options: s,
	}
}

func isEssentialCall(syscall string) bool {
	switch syscall {
	case "close", "exit", "execve", "exit_group":
		return true
	}
	return false
}

func (s *BruteForceSource) canRunBlockingSyscall(syscall string) bool {
	if isEssentialCall(syscall) {
		return false
	}

	tmpSyscalls := s.excludeItemFromSlice(s.options, syscall)
	err := s.runner.RunWithSeccomp(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			specs.LinuxSyscall{Names: tmpSyscalls, Action: specs.ActAllow},
		},
	})

	return err == nil
}

func (s *BruteForceSource) GetSystemCalls() (*specs.LinuxSyscall, error) {
	var wg sync.WaitGroup
	sChan := make(chan string)

	validate := func(sc string) {
		if !s.canRunBlockingSyscall(sc) {
			sChan <- sc
		}
		wg.Done()
	}
	wg.Add(len(s.options))

	for _, syscall := range s.options {
		go validate(syscall)
	}

	go func() {
		wg.Wait()
		close(sChan)
	}()

	mustHaves := make([]string, 0, 50)
	for {
		if sc, ok := <-sChan; ok {
			mustHaves = append(mustHaves, sc)
		} else {
			break
		}
	}

	return &specs.LinuxSyscall{
		Action: specs.ActAllow,
		Names:  mustHaves,
	}, nil
}

func (s *BruteForceSource) indexesOf(source []string, item string) []int {
	indexes := make([]int, 0, len(source))
	for i, currentItem := range source {
		if currentItem == item {
			indexes = append(indexes, i)
		}
	}

	return indexes
}

func (s *BruteForceSource) excludeItemFromSlice(source []string, itemToExclude string) []string {
	indexes := s.indexesOf(source, itemToExclude)
	if len(indexes) == 0 {
		return source
	}

	newSlice := make([]string, 0, len(source))
	nextFirstIndex := 0
	for _, i := range indexes {
		newSlice = append(newSlice, source[nextFirstIndex:i]...)
		nextFirstIndex = i + 1
	}

	newSlice = append(newSlice, source[nextFirstIndex:]...)
	return newSlice
}
