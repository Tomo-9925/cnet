package policy_test

import (
	"math/rand"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
)

var (

)

func TestSocketIsDefined(t *testing.T) {
	const (
		satisfy bool = iota % 2 == 0
		notSatisfy
	)
	var (
		testSocketLocalIP net.IP = net.ParseIP("192.168.1.2")
		portRand *rand.Rand = rand.New(rand.NewSource(1))
		testCommunicatedContainer map[bool]*container.Container = map[bool]*container.Container{
			satisfy: {ID: "49dae530fd5fee674a6b0d3da89a380fc93746095e7eca0f1b70188a95fd5d71", Name: testContainerName},
			notSatisfy: {ID: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Name: "cnet_quic_test"},
		}
		testCommunicatedProcess map[bool]*proc.Process = map[bool]*proc.Process{
			satisfy: {ID: 1,Path: testProcessPath, Executable: testProcessExecutable},
			notSatisfy: {ID: 2, Path: "/usr/local/bin/curl", Executable: "curl"},
		}
		testTargetSocket map[bool]*proc.Socket = map[bool]*proc.Socket {
			satisfy: {Protocol: testSocketProtocol, LocalIP: testSocketLocalIP, RemoteIP: testSocketRemoteIP, LocalPort: uint16(portRand.Uint32()), RemotePort: testSocketRemotePort},
			notSatisfy: {Protocol: layers.LayerTypeUDP, LocalIP: net.ParseIP("192.168.1.3"), RemoteIP: testSocketRemoteIP, LocalPort: uint16(portRand.Uint32()), RemotePort: 443},
		}
	)

	for satisfyContainer, targetContainer := range testCommunicatedContainer {
		for satisfyProcess, targetProcess := range testCommunicatedProcess {
			for satisfySocket, targetSocket := range testTargetSocket {
				if satisfyContainer && satisfyProcess && satisfySocket {
					if !expectedPolicies.IsDefined(targetContainer, targetProcess, targetSocket) {
						t.Error("defined test communication not passed")
					}
					targetSocket.LocalPort = uint16(portRand.Uint32())
					continue
				}
				if expectedPolicies.IsDefined(targetContainer, targetProcess, targetSocket) {
					t.Error("undefined test communication passed", targetContainer, targetProcess, targetSocket)
				}
				targetSocket.LocalPort = uint16(portRand.Uint32())
			}
		}
	}
}

