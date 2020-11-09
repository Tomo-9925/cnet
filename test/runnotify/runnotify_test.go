package runnotify_test

import (
	"testing"

	"github.com/tomo-9925/cnet/pkg/runnotify"
)

func TestRunnotify(t *testing.T) {
	runCh := make(chan string)
	killCh := make(chan string)
	runErrCh := make(chan error)
	runNotifyApi:= runnotify.NewAPI(runCh,killCh,runErrCh)
	if runNotifyApi.Messages == nil{
		t.Fatal("failed to innitialize runNotifyApi(Messages is nil)")
	}else if runNotifyApi.Err == nil{
		t.Fatal("failed to innitialize runNotifyApi(Err is nil)")
	}
}
