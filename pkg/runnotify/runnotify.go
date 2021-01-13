package runnotify

import (
	"path/filepath"

	"github.com/docker/docker/api/types/events"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/docker"
)

// API is the collection of channels that receive container events from Docker Engine API
type API struct {
	Messages <-chan events.Message
	Err      <-chan error
	runCh    chan string
	killCh   chan string
	errCh    chan error
}

// NewAPI return the RunNotify.API
func NewAPI(runCh chan string, killCh chan string, errCh chan error) *API {
	argFields := logrus.WithFields(logrus.Fields{
		"run_channel": runCh,
		"kill_channel": killCh,
		"error_channel": errCh,
	})
	argFields.Debug("trying to make runnotify api")

	runNotifyAPI := API{Messages: nil, runCh: runCh, killCh: killCh, errCh: errCh}
	runNotifyAPI.Messages, runNotifyAPI.Err = docker.NewEventWatcher()

	argFields.WithField("run_notify_api", runNotifyAPI).Debug("runnotify api made")
	return &runNotifyAPI
}

// Start starts monitoring
func (runNotifyAPI *API) Start() {
	apiField := logrus.WithField("run_notify_api", runNotifyAPI)
	apiField.Debug("trying to start docker event monitoring")

	defer close(runNotifyAPI.runCh)
	defer close(runNotifyAPI.killCh)
	defer close(runNotifyAPI.errCh)

	lastRun := ""
	lastKill := ""
	for {
		select {
		case msg := <-runNotifyAPI.Messages:
			apiField.WithField("message", msg).Debug("docker event received")
			switch msg.Action{
			case "start", "unpause":
				cid := filepath.Base(msg.ID)
				if lastRun == cid {
					continue
				}
				runNotifyAPI.runCh <- cid
				lastRun = cid
			case "pause", "die":
				cid := filepath.Base(msg.ID)
				if cid == lastKill {
					continue
				}
				runNotifyAPI.killCh <- cid
				lastKill = cid
			}
		case err := <-runNotifyAPI.Err:
			apiField.WithField("error", err).Debug("docker events error received")
			runNotifyAPI.errCh <- err
		}
	}
}
