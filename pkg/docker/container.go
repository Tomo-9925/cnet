package docker

import (
	"context"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	basedContainer "github.com/tomo-9925/cnet/pkg/container"
)

type Containers basedContainer.Containers

func fetchContainerInspection(cid string) (container *basedContainer.Container, err error) {
	cidField := logrus.WithField("container_id", cid)
	cidField.Debug("trying to fetch docker container inspection")

	var inspect types.ContainerJSON
	inspect, err = cli.ContainerInspect(context.Background(), cid)
	if err != nil {
		cidField.WithField("error", err).Debug("container inspection not fetched")
		return
	}

	cidField.WithField("container_inspection", inspect).Debug("container inspection fetched")
	ipAddresses := make([]net.IP, 0, len(inspect.NetworkSettings.Networks))
	for _, network := range inspect.NetworkSettings.Networks {
		ipAddresses = append(ipAddresses, net.ParseIP(network.IPAddress))
	}
	container = &basedContainer.Container{ID: inspect.ID, IPAddresses: ipAddresses, Name: inspect.Name, Pid: inspect.State.Pid}
	return
}

// InitializeContainers return the information slice of Docker container.
func InitializeContainers() (containers *Containers, err error) {
	logrus.Debugln("trying to fetch docker container inspections")

	var dockerContainerList []types.Container
	dockerContainerList, err = cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		logrus.WithField("error", err).Debug("container list not fetched")
		return
	}

	containers = &Containers{List: make([]*container.Container, len(dockerContainerList))}
	for i, dockerContainer := range dockerContainerList {
		var container *container.Container
		container, err = fetchContainerInspection(dockerContainer.ID)
		if err != nil {
			logrus.WithField("error", err).Debug("container inspections not fetched")
			return
		}
		containers.List[i] = container
	}

	logrus.WithField("containers", containers).Debug("container inspections fetched")
	return
}

// AddContainer add container information to Containers List
func (c *Containers)AddContainer(cid string) (err error) {
	var container *basedContainer.Container
	container, err = fetchContainerInspection(cid)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"containers": c,
			"added_container_id": cid,
		}).Debug("failed to add container inspection")
		return
	}
	c.RWMutex.Lock()
	c.List = append(c.List, container)
	c.RWMutex.Unlock()
	logrus.WithFields(logrus.Fields{
		"containers": c,
		"added_container_id": cid,
	}).Debug("container inspection added")
	return
}

// RemoveContainer removes container information from Containers List.
func (c *Containers)RemoveContainer(cid string) {
	for i, container := range c.List {
		if container.ID == cid {
			c.RWMutex.Lock()
			c.List = append(c.List[:i], c.List[i+1:]...)
			c.RWMutex.Unlock()
			logrus.WithFields(logrus.Fields{
				"containers": c,
				"removed_container_id": cid,
			}).Debug("container inspection removed")
			return
		}
	}
}
