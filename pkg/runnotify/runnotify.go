package runnotify

import (
	"path/filepath"

	"github.com/docker/docker/api/types/events"
	"github.com/tomo-9925/cnet/pkg/container"
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
	runNotifyAPI := API{Messages: nil, runCh: runCh, killCh: killCh, errCh: errCh}
	runNotifyAPI.Messages, runNotifyAPI.Err = container.NewWatcher()

	return &runNotifyAPI
}

// Start starts monitoring
func (runNotifyAPI *API) Start() {
	defer close(runNotifyAPI.runCh)
	defer close(runNotifyAPI.killCh)
	defer close(runNotifyAPI.errCh)

	lastRun := ""
	lastKill := ""
	for {
		select {
		case msg := <-runNotifyAPI.Messages:
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
			runNotifyAPI.errCh <- err
		}
	}
}
