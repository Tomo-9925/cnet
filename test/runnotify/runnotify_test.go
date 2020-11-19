package runnotify_test

import (
	"testing"

	"github.com/tomo-9925/cnet/pkg/runnotify"
)

func TestRunnotify(t *testing.T) {
	runCh := make(chan string)
	killCh := make(chan string)
	runErrCh := make(chan error)
	runNotifyAPI:= runnotify.NewAPI(runCh,killCh,runErrCh)
	if runNotifyAPI.Messages == nil{
		t.Fatal("failed to innitialize runNotifyAPI(Messages is nil)")
	}else if runNotifyAPI.Err == nil{
		t.Fatal("failed to innitialize runNotifyAPI(Err is nil)")
	}
}
