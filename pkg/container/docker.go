package container

import (
	"context"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

var dockerCli *client.Client

func init() {
	logrus.Debug("trying to initialize docker engine api client")
	var err error
	dockerCli, err = client.NewEnvClient()
	cliField := logrus.WithField("client", *dockerCli)
	if err != nil {
		cliField.WithField("error", err).Fatal("faild to initialize docker engine api client")
	}
	cliField.Debug("docker engine api client initialized")
}

// FetchDockerContainerInspections return the information slice of Docker container.
func FetchDockerContainerInspections() (containers []*Container, err error) {
	logrus.Debugln("trying to fetch docker container inspections")

	var dockerContainerList []types.Container
	dockerContainerList, err = dockerCli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		logrus.WithField("error", err).Debug("container list not fetched")
		return
	}

	for _, dockerContainer := range dockerContainerList {
		var container *Container
		container, err = FetchDockerContainerInspection(dockerContainer.ID)
		if err != nil {
			logrus.WithField("error", err).Debug("container inspections not fetched")
			return
		}
		containers = append(containers, container)
	}

	logrus.WithField("containers", containers).Debug("container inspections fetched")
	return
}

// FetchDockerContainerInspection return the information of Docker container.
func FetchDockerContainerInspection(cid string) (container *Container, err error) {
	cidField := logrus.WithField("container_id", cid)
	cidField.Debug("trying to fetch docker container inspection")

	var inspect types.ContainerJSON
	inspect, err = dockerCli.ContainerInspect(context.Background(), cid)
	if err != nil {
		cidField.WithField("error", err).Debug("container inspection not fetched")
		return
	}

	cidField.WithField("container_inspection", inspect).Debug("container inspection fetched")
	container = &Container{inspect.ID, net.ParseIP(inspect.NetworkSettings.IPAddress), inspect.Name, inspect.State.Pid}
	return
}

// RemoveContainerFromSlice removes container information from slice.
func RemoveContainerFromSlice(containers []*Container, cid string) (result []*Container) {
	for _, container := range containers {
		if container.ID != cid {
			result = append(result, container)
		}
	}

	logrus.WithFields(logrus.Fields{
		"containers": result,
		"removed_container_id": cid,
	}).Debug("container inspection removed")
	return
}

// NewWatcher starts monitoring docker events.
func NewWatcher() (msg <-chan events.Message, err <-chan error) {
	logrus.Debugln("trying to fetch docker container inspection")

	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "start")
	filter.Add("event", "unpause")
	filter.Add("event", "pause")
	filter.Add("event", "die")

	msg, err = dockerCli.Events(context.Background(), types.EventsOptions{Filters: filter})
	return
}
