package seccomp

import (
	"archive/tar"
	"bytes"
	"io"
	"log"
	"os"
	"sync"
	"testing"

	"github.com/pjbgf/go-test/should"

	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const localImageName string = "zaz-local-test-image"
const localImageNameLatest string = localImageName + ":latest"

func TestGetFullTag(t *testing.T) {
	assertThat := func(assumption, image, expectedTag string) {
		should := should.New(t)

		r, _ := NewDockerRunner(image, "")
		actualTag := r.getFullTag(image)

		should.BeEqual(expectedTag, actualTag, assumption)
	}

	assertThat("should append :latest when image has no tag",
		"image_repo", "image_repo:latest")

	assertThat("should make no changes if image already has tag",
		"image_repo2:someTag", "image_repo2:someTag")
}

func TestDockerRunner_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
		return
	}

	var wg sync.WaitGroup
	assertThat := func(assumption, image, cmd string, profile *specs.LinuxSeccomp,
		shouldErr bool) {
		should := should.New(t)
		r, _ := NewDockerRunner(image, cmd)

		err := r.RunWithSeccomp(profile)
		hasErrored := err != nil

		should.BeEqual(shouldErr, hasErrored, assumption)
		wg.Done()
	}

	wg.Add(5)

	removeImageFromCache("alpine:latest")
	assertThat("should pull image if does not exist locally",
		"alpine:latest",
		"echo hi",
		nil,
		true)

	removeImageFromCache(localImageNameLatest)
	buildTestImage()
	go assertThat("should support use of local images",
		localImageName,
		"",
		nil,
		false)

	go assertThat("should support use of local images with tag",
		localImageNameLatest,
		"",
		nil,
		false)

	go assertThat("should run container with command",
		localImageNameLatest,
		"echo hi",
		nil,
		false)

	go assertThat("should error if profile is too restrictive",
		localImageNameLatest,
		"echo hi",
		&specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
		true)

	wg.Wait()
}

func removeImageFromCache(image string) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic("could not remote image from cache")
	}

	imgs, err := cli.ImageList(ctx, types.ImageListOptions{Filters: filters.NewArgs(filters.KeyValuePair{Key: "dangling", Value: "false"})})
	if err != nil {
		panic("could not list images")
	}

	for _, img := range imgs {
		for _, repos := range img.RepoTags {
			if repos == image {
				cli.ImageRemove(ctx, img.ID, types.ImageRemoveOptions{Force: true})
			}
		}
	}
}

func buildTestImage() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic("cannot build local image")
	}

	if _, err = cli.ImagePull(ctx, "alpine:latest", types.ImagePullOptions{}); err != nil {
		panic("cannot pull alpine:latest")
	}

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	defer tw.Close()

	dockerFileContent := "FROM alpine:latest\n"
	tarHeader := &tar.Header{
		Name: "Dockerfile",
		Size: int64(len(dockerFileContent)),
	}
	err = tw.WriteHeader(tarHeader)
	if err != nil {
		log.Fatal(err, " :unable to write tar header")
	}
	_, err = tw.Write([]byte(dockerFileContent))
	if err != nil {
		log.Fatal(err, " :unable to write tar body")
	}
	dockerFileTarReader := bytes.NewReader(buf.Bytes())

	imageBuildResponse, err := cli.ImageBuild(
		ctx,
		dockerFileTarReader,
		types.ImageBuildOptions{
			Tags:       []string{localImageNameLatest},
			PullParent: true,
			Context:    dockerFileTarReader,
			Remove:     true})
	if err != nil {
		log.Fatal(err, " :unable to build docker image")
	}
	defer imageBuildResponse.Body.Close()
	_, err = io.Copy(os.Stdout, imageBuildResponse.Body)
	if err != nil {
		log.Fatal(err, " :unable to read image build response")
	}
}
