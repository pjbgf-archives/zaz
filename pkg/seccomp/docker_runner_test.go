package seccomp

import (
	"archive/tar"
	"bytes"
	"log"
	"sync"
	"testing"

	"github.com/pjbgf/go-test/should"

	"context"

	"github.com/docker/docker/api/types"
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

	wg.Wait()
}

func buildTestImage() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic("cannot build local image")
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
}
