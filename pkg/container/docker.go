package container

import (
	"context"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

var dockerCli *client.Client

// GetDockerContainerInformations return the information slice of Docker container.
func GetDockerContainerInformations() ([]*Container, error) {
	var containerInformations []*Container

	// Initialize client for the Docker Engine API
	dockerCli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}

	// Get container list
	containers, err := dockerCli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	// Get container informations
	for _, container := range containers {
		containerInformation, err := GetDockerContainerInformation(container.ID)
		if err != nil {
			return nil, err
		}
		containerInformations = append(containerInformations, containerInformation)
	}

	return containerInformations, nil
}

// GetDockerContainerInformation return the information of Docker container.
func GetDockerContainerInformation(containerID string) (*Container, error) {
	var containerInformation *Container

	// Get container information
	inspect, err := dockerCli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return nil, err
	}

	containerInformation = &Container{
		ID:   inspect.ID,
		IP:   net.ParseIP(inspect.NetworkSettings.IPAddress),
		Name: inspect.Name,
		Pid:  inspect.State.Pid,
	}

	return containerInformation, nil
}

func RemoveContainer(containers []*Container, cid string) []*Container {
	result := []*Container{}
	for _, container := range containers {
		if container.ID != cid {
			result = append(result, container)
		}
	}
	return result
}
