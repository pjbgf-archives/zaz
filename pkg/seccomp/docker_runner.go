package seccomp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var executionTimeout time.Duration = 1 * time.Minute

// DockerRunner represents a runner for docker.
type DockerRunner struct {
	Image   string
	Command string
}

// NewDockerRunner initialises DockerRunner.
func NewDockerRunner(img, cmd string) (*DockerRunner, error) {
	return &DockerRunner{
		Image:   img,
		Command: cmd,
	}, nil
}

func (r *DockerRunner) ensureImageWasPulled(image string) error {
	ctx := context.Background()
	if cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation()); err == nil {
		imgs, err := cli.ImageList(ctx, types.ImageListOptions{Filters: filters.NewArgs(filters.KeyValuePair{Key: "dangling", Value: "false"})})
		if err != nil {
			return err
		}

		fullTag := r.getFullTag(image)
		for _, img := range imgs {
			for _, tag := range img.RepoTags {
				if tag == fullTag {
					return nil
				}
			}
		}

		if _, err = cli.ImagePull(ctx, image, types.ImagePullOptions{}); err == nil {
			return nil
		}
	}

	return errors.New("image could not be pulled")
}

func (r *DockerRunner) getFullTag(image string) string {
	imageParts := strings.Split(image, ":")
	tagName := "latest"
	if len(imageParts) > 1 {
		tagName = imageParts[1]
	}

	return imageParts[0] + ":" + tagName
}

// RunWithSeccomp creates a container and runs the defined command.
func (r *DockerRunner) RunWithSeccomp(profile *specs.LinuxSeccomp) (err error) {
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

		err = r.ensureImageWasPulled(r.Image)
		if err != nil {
			return err
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
		case sts := <-statusCh:
			if sts.StatusCode > 0 {
				return fmt.Errorf("error on status channel")
			}
		case <-time.After(executionTimeout):
			go cli.ContainerStop(ctx, resp.ID, nil)
			return fmt.Errorf("container execution timed out")
		}

		status, err := cli.ContainerInspect(ctx, resp.ID)
		if err != nil {
			return fmt.Errorf("error running container. err: %v", err)
		}
		if status.State != nil && status.State.ExitCode > 0 {
			return fmt.Errorf("error running container. exit code: %d", status.State.ExitCode)
		}
	}

	return err
}
