package policy

import (
	"net"

	"github.com/google/gopacket"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
)

// Policy is information about the communication of container needed to analyze communications of container.
type Policy struct {
	Container      *container.Container
	Communications []*Communication
}

// Communication is information about process and socket needed to analyze communications of container.
type Communication struct {
	Processes []*proc.Process
	Sockets   []*Socket
}

// Socket is information about information needed to control network.
type Socket struct {
	Protocol   gopacket.LayerType
	RemoteIP   *net.IPNet
	LocalPort  uint16
	RemotePort uint16
}

// Policies is slice of Policy structure.
type Policies []*Policy

// IsDefined reports whether the policy is defined.
func (p *Policies) IsDefined(targetContainer *container.Container, targetProcess *proc.Process, targetSocket *proc.Socket) bool
