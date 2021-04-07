package scanner

import (
	"fmt"
	"os/exec"
)

// DockerClient is a thin client for docker
type DockerClient interface {
	PullImage(image string) error
	RmiImage(image string) error
}

type dockerClient struct {
}

// NewDockerClient creates a new DockerClient
func NewDockerClient() DockerClient {
	return &dockerClient{}
}

func (d *dockerClient) PullImage(image string) error {
	command := exec.Command("docker", "pull", image)
	output, err := command.CombinedOutput()
	if err != nil {
		return dockerError(fmt.Sprintf("error while pulling for image %s", image), output, err)
	}
	return nil
}

func (d *dockerClient) RmiImage(image string) error {
	command := exec.Command("docker", "rmi", image)
	output, err := command.CombinedOutput()
	if err != nil {
		return dockerError(fmt.Sprintf("error while deleting image %s", image), output, err)
	}
	return nil
}

func dockerError(message string, output []byte, err error) error {
	var outputAsString string
	if output != nil {
		outputAsString = string(output)
	}
	return fmt.Errorf("%s. Output: %s, Error: %v", message, outputAsString, err)
}
