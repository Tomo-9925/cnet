package proc_test

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	cnetContainer "github.com/tomo-9925/cnet/pkg/container"
	cnetNetwork "github.com/tomo-9925/cnet/pkg/network"
	"github.com/tomo-9925/cnet/pkg/proc"
)

var (
	// Docker Engine API settings
	ctx context.Context = context.Background()
	netcatContainerName string = "cnet_netcat_test"
	netcatImage string = "docker.io/library/busybox"
	netcatImageName string = "busybox"
	netcatDestination string = "158.217.2.147"
	netcatPort uint16 = 80
	netcatContainerConfig *container.Config = types.ContainerCreateConfig{
			Name: netcatContainerName,
			Config: &container.Config{
				Image: netcatImageName,
				Cmd: []string{"nc", netcatDestination, strconv.FormatUint(uint64(netcatPort), 10)},  // Web Server of Kansai University
			},
	}.Config
	netcatHostConfig *container.HostConfig = &container.HostConfig{
		AutoRemove: true,
	}

	// iptables settings
	chainName string = "DOCKER-USER"
	ruleNum   uint16 = 1
	protocol  string = "all"
	queueNum  uint16 = 0

	// NFQueue settings
	maxPacketsInQueue uint32 = 100
)

func TestIdentifyTCPCommunication(t *testing.T) {
	// Make netcat Container
	cli, err := client.NewEnvClient()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := cli.ImagePull(ctx, netcatImage, types.ImagePullOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(os.Stdout, reader)
	if err != nil {
		t.Fatal(err)
	}

	// Setting iptables
	if err := cnetNetwork.InsertNFQueueRule(chainName, protocol, ruleNum, queueNum); err != nil {
		t.Fatal(err)
	}
	defer func(){
		err := cnetNetwork.DeleteNFQueueRule(chainName, protocol, queueNum)
		if err != nil {
			t.Error(err)
		}
		}()

	// Setting NFQueue
	queue, err := netfilter.NewNFQueue(queueNum, maxPacketsInQueue, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	packets := queue.GetPackets()

	// Create Container
	// NOTE: If the server application container is set up and verified, it does not go through the DOCKER-USER chain.
	apiResp, err := cli.ContainerCreate(ctx, netcatContainerConfig, netcatHostConfig, &network.NetworkingConfig{}, netcatContainerName)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.ContainerStart(ctx, apiResp.ID, types.ContainerStartOptions{}); err != nil{
		t.Fatal(err)
	}
	defer func(){
		err := cli.ContainerStop(ctx, apiResp.ID, nil)
		if err != nil {
			t.Error(err)
		}
		}()

	// Get container information
	inspect, err := cli.ContainerInspect(ctx, apiResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	startedContainer := &cnetContainer.Container{
		ID: inspect.ID,
		IPAddresses: []net.IP{net.ParseIP(inspect.NetworkSettings.IPAddress)},
		Name: inspect.Name,
		Pid: inspect.State.Pid,
	}

	// Get packet
	p := <-packets

	// Get Socket Information
	socket, _, err := proc.CheckSocketAndCommunicatedContainer(&p.Packet, []*cnetContainer.Container{startedContainer})
	if err != nil {
		t.Fatal(err)
	}
	if !socket.LocalIP.Equal(startedContainer.IPAddresses[0]) {
		t.Error("local ip address not located correctly")
	}
	if !socket.RemoteIP.Equal(net.ParseIP(netcatDestination)) {
		t.Error("remote ip address not located correctly")
	}
	if socket.RemotePort != netcatPort {
		t.Error("remote port number not get correctly")
	}

	// Get Process of container information
	communicatedProcess, err := proc.IdentifyProcessOfContainer(socket, startedContainer, &p.Packet)
	if err != nil {
		t.Fatal(err)
	}
	if communicatedProcess.Executable != "nc" {
		t.Error("executable not get correctly")
	}
	if communicatedProcess.Path != "/bin/nc" {
		t.Error("path not get correctly")
	}
}
