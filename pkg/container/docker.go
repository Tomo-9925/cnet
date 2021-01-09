package container

import (
	"context"
	"io/ioutil"
	"net"
	"strconv"
	"unsafe"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

var (
	// DockerdPID is docker daemon pid
	DockerdPID int

	dockerCli  *client.Client
)

func init() {
	// Initialize docker client
	logrus.Debug("trying to initialize docker engine api client")
	var err error
	dockerCli, err = client.NewEnvClient()
	cliField := logrus.WithField("client", *dockerCli)
	if err != nil {
		cliField.WithField("error", err).Fatal("faild to initialize docker engine api client")
	}
	cliField.Debug("docker engine api client initialized")

	// Retrieve dockerd pid
	var file []byte
	file, err = ioutil.ReadFile("/var/run/docker.pid")
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to retrieve dockerd process id")
	}
	DockerdPID, err = strconv.Atoi(*(*string)(unsafe.Pointer(&file)))
	if err != nil {
		logrus.WithField("error", err).Fatal("failed to retrieve dockerd process id")
	}
}

// FetchDockerContainerInspections return the information slice of Docker container.
func FetchDockerContainerInspections() (containers *Containers, err error) {
	logrus.Debugln("trying to fetch docker container inspections")

	var dockerContainerList []types.Container
	dockerContainerList, err = dockerCli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		logrus.WithField("error", err).Debug("container list not fetched")
		return
	}

	containers = &Containers{List: make([]*Container, len(dockerContainerList))}
	for i, dockerContainer := range dockerContainerList {
		var container *Container
		container, err = FetchDockerContainerInspection(dockerContainer.ID)
		if err != nil {
			logrus.WithField("error", err).Debug("container inspections not fetched")
			return
		}
		containers.List[i] = container
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
	ipAddresses := make([]net.IP, 0, len(inspect.NetworkSettings.Networks))
	for _, network := range inspect.NetworkSettings.Networks {
		ipAddresses = append(ipAddresses, net.ParseIP(network.IPAddress))
	}
	container = &Container{inspect.ID, ipAddresses, inspect.Name, inspect.State.Pid}
	return
}

// AddDockerContainerToList add container information to Containers List
func AddDockerContainerToList(containers *Containers, cid string) (err error) {
	var container *Container
	container, err = FetchDockerContainerInspection(cid)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"containers": containers,
			"added_container_id": cid,
		}).Debug("failed to add container inspection")
		return
	}
	containers.RWMutex.Lock()
	containers.List = append(containers.List, container)
	containers.RWMutex.Unlock()
	logrus.WithFields(logrus.Fields{
		"containers": containers,
		"added_container_id": cid,
	}).Debug("container inspection added")
	return
}

// RemoveDockerContainerFromList removes container information from Containers List.
func RemoveDockerContainerFromList(containers *Containers, cid string) {
	for i, container := range containers.List {
		if container.ID == cid {
			containers.RWMutex.Lock()
			containers.List = append(containers.List[:i], containers.List[i+1:]...)
			containers.RWMutex.Unlock()
			logrus.WithFields(logrus.Fields{
				"containers": containers,
				"removed_container_id": cid,
			}).Debug("container inspection removed")
			return
		}
	}
}

// NewDockerEventWatcher starts monitoring docker events.
func NewDockerEventWatcher() (msg <-chan events.Message, err <-chan error) {
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
