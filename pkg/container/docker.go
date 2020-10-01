package container

import (
	"context"
	"net"

	"github.com/docker/docker/api/types/filters"

	"github.com/docker/docker/api/types/events"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

var dockerCli *client.Client

// GetDockerContainerInformations return the information slice of Docker container.
func GetDockerContainerInformations() ([]*Container, error) {
	var containerInformations []*Container

	// Initialize client for the Docker Engine API
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	dockerCli = cli
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

	// Get container information
	inspect, err := dockerCli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return nil, err
	}

	return &Container{
		ID:   inspect.ID,
		IP:   net.ParseIP(inspect.NetworkSettings.IPAddress),
		Name: inspect.Name,
		Pid:  inspect.State.Pid,
	}, nil
}

func RemoveContainerFromSlice(containers []*Container, cid string) []*Container {
	result := []*Container{}
	for _, container := range containers {
		if container.ID != cid {
			result = append(result, container)
		}
	}
	return result
}

func NewWatcher() (<-chan events.Message, <-chan error) {
	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "create")
	filter.Add("event", "destroy")

	msg, err := dockerCli.Events(context.Background(), types.EventsOptions{
		Filters: filter,
	})
	return msg, err
}
