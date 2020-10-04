package container

import (
	"context"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// GetDockerContainerInformations returns the slice of container information about existing Docker container.
func GetDockerContainerInformations() ([]*Container, error) {
	var containerInformations []*Container

	// Initialize client for the Docker Engine API
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}

	// Get container list
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	// Get container informations
	for _, container := range containers {
		inspect, err := cli.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			return nil, err
		}
		containerInformations = append(containerInformations, &Container{
			ID:   inspect.ID,
			IP:   net.ParseIP(inspect.NetworkSettings.IPAddress),
			Name: inspect.Name,
			Pid:  inspect.State.Pid,
		})
	}

	return containerInformations, nil
}
