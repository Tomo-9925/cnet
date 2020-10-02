package proc_test

import (
	"context"
	"net"
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
	netcatImage string = "docker.io/subfuzion/netcat"
	netcatContainerConfig *container.Config = types.ContainerCreateConfig{
			Name: netcatContainerName,
			Config: &container.Config{
				Image: netcatImage,
				Cmd: []string{"158.217.2.147", "80"},  // Web Server of Kansai University
			},
	}.Config
	netcatHostConfig *container.HostConfig = &container.HostConfig{}

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
	_, err = cli.ImagePull(ctx, netcatImage, types.ImagePullOptions{})
	if err != nil {
		t.Fatal(err)
	}

		// Setting iptables
	if err := cnetNetwork.InsertNFQueueRule(chainName, protocol, ruleNum, queueNum); err != nil {
		t.Fatal(err)
	}
	defer cnetNetwork.DeleteNFQueueRule(chainName, protocol, queueNum)

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
	defer cli.ContainerRemove(ctx, apiResp.ID, types.ContainerRemoveOptions{})

	// Get container information
	inspect, err := cli.ContainerInspect(ctx, apiResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	pContainer := &cnetContainer.Container{
		ID: inspect.ID,
		IP: net.ParseIP(inspect.NetworkSettings.IPAddress),
		Name: inspect.Name,
		Pid: inspect.State.Pid,
	}

	// Get packet
	p := <-packets

	// Get Socket Information
	pSocket, _, err := proc.CheckSocketAndCommunicatedContainer(&p.Packet, []*cnetContainer.Container{pContainer})
	if err != nil {
		t.Fatal(err)
	}
	if !pSocket.LocalIP.Equal(pContainer.IP) {
		t.Error("local ip address not located correctly")
	}
	if pSocket.RemotePort != 80 {
		t.Error("remote port number not get correctly")
	}

	// Get Process of container information
	pProcess, err := proc.IdentifyProcessOfContainer(pSocket, pContainer, &p.Packet)
	if err != nil {
		t.Fatal(err)
	}
	if pProcess.Executable != "nc" {
		t.Error("executable not get correctly")
	}
	if pProcess.Path != "/usr/bin/nc" {
		t.Error("path not get correctly")
	}
}
