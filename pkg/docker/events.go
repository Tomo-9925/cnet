package docker

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/sirupsen/logrus"
)

// NewEventWatcher starts monitoring docker events.
func NewEventWatcher() (msg <-chan events.Message, err <-chan error) {
	logrus.Debugln("trying to fetch docker container inspection")

	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "start")
	filter.Add("event", "unpause")
	filter.Add("event", "pause")
	filter.Add("event", "die")

	msg, err = cli.Events(context.Background(), types.EventsOptions{Filters: filter})
	return
}
