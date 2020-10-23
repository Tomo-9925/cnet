package policy_test

import (
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/k0kubun/pp"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
)

func TestSocketIsDefined(t *testing.T) {
	const (
		satisfy bool = iota % 2 == 0
		notSatisfy
	)
	var (
		testCommunicatedContainer map[bool]*container.Container = map[bool]*container.Container{
			satisfy: {Name: testContainerName},
			notSatisfy: {Name: "cnet_quic_test"},
		}
		testCommunicatedProcess map[bool]*proc.Process = map[bool]*proc.Process{
			satisfy: {Executable: testProcessExecutable},
			notSatisfy: {Executable: "curl"},
		}
		testTargetSocket map[bool]*proc.Socket = map[bool]*proc.Socket {
			satisfy: {Protocol: testSocketProtocol, RemoteIP: testSocketRemoteIP, RemotePort: testSocketRemotePort},
			notSatisfy: {Protocol: layers.LayerTypeUDP, RemoteIP: testSocketRemoteIP, RemotePort: 443},
		}
	)

	for satisfyContainer, targetContainer := range testCommunicatedContainer {
		for satisfyProcess, targetProcess := range testCommunicatedProcess {
			for satisfySocket, targetSocket := range testTargetSocket {
				if satisfyContainer && satisfyProcess && satisfySocket {
					if !expectedPolicies.IsDefined(targetContainer, targetProcess, targetSocket) {
						t.Error("defined test communication not passed")
						pp.Println(targetContainer, targetProcess, targetSocket)
					}
					continue
				}
				if expectedPolicies.IsDefined(targetContainer, targetProcess, targetSocket) {
					t.Error("undefined test communication passed:")
					pp.Println(targetContainer, targetProcess, targetSocket)
				}
			}
		}
	}
}

