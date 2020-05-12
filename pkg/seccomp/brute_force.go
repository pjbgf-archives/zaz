package seccomp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// BruteForceSource represents a system calls source based on a brute force approach.
type BruteForceSource struct {
	options []string
	runner  BruteForceRunner
}

// BruteForceRunner defines the interface for brute force runners.
type BruteForceRunner interface {
	RunWithSeccomp(profile *specs.LinuxSeccomp) error
}

// DockerRunner represents a runner for docker.
type DockerRunner struct {
	Image   string
	Command string
}

// NewDockerRunner initialises DockerRunner.
func NewDockerRunner(img, cmd string) (*DockerRunner, error) {
	err := ensureImageWasPulled(img)
	if err != nil {
		return nil, err
	}

	return &DockerRunner{
		Image:   img,
		Command: cmd,
	}, nil
}

func ensureImageWasPulled(image string) error {
	ctx := context.Background()
	if cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation()); err == nil {
		if _, err = cli.ImagePull(ctx, image, types.ImagePullOptions{}); err == nil {
			return nil
		}
	}

	return errors.New("image could not be pulled")
}

// RunWithSeccomp creates a container and runs the defined command.
func (r *DockerRunner) RunWithSeccomp(profile *specs.LinuxSeccomp) error {
	ctx := context.Background()
	if cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation()); err == nil {
		hostCfg := container.HostConfig{SecurityOpt: []string{"no-new-privileges"}, AutoRemove: true}
		cfg := container.Config{Image: r.Image, Tty: false, AttachStdout: false, AttachStderr: false}

		if r.Command != "" {
			cfg.Cmd = strings.Fields(r.Command)
		}

		if profile != nil {
			content, err := json.Marshal(profile)
			if err != nil {
				panic(err)
			}
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
			return errors.New("error running container")
		}
	}

	return errors.New("error running container")
}

// NewBruteForceSource initialises BruteForceSource.
func NewBruteForceSource(runner BruteForceRunner) *BruteForceSource {
	s := getMostFrequentSyscalls()
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

// GetSystemCalls returns all system calls found by brute forcing the profile using a runner.
func (s *BruteForceSource) GetSystemCalls() (*specs.LinuxSyscall, error) {
	mustHaves := make([]string, 0, 60)
	process := func(scs []string) []string {
		items := make([]string, 0, 60)
		for _, syscall := range scs {
			if !s.canRunBlockingSyscall(syscall) {
				items = append(items, syscall)
			}
		}
		return items
	}

	mustHaves = append(mustHaves, process(s.options)...)

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
