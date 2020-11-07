package policy

import (
	"bytes"
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

// IsMatched reports whether content of the proc.Socket matches policy.Socket.
func (s *Socket) IsMatched(x *proc.Socket) bool {
	if s.Protocol != x.Protocol {
		return false
	} else if s.LocalPort != 0 && s.LocalPort != x.LocalPort {
		return false
	} else if s.RemotePort != 0 && s.RemotePort != x.RemotePort {
		return false
	} else if !bytes.Equal(s.RemoteIP.Mask, net.IPMask{}) && !s.RemoteIP.Contains(x.RemoteIP) {
		return false
	} else if !bytes.Equal(s.RemoteIP.IP, net.IP{}) && !s.RemoteIP.IP.Equal(x.RemoteIP) {
		return false
	}
	return true
}

// Policies is slice of Policy structure.
type Policies []*Policy

// IsDefined reports whether the policy is defined.
func (p *Policies) IsDefined(communicatedContainer *container.Container, communicatedProcess *proc.Process, targetSocket *proc.Socket) bool {
	// HACK: So many indents that it's hard to understand. The structure of Policies may need to be rethought.
	for _, policy := range *p {
		if !policy.Container.Equal(communicatedContainer) {
			continue
		}
		for _, communication := range policy.Communications {
			for _, process := range communication.Processes {
				if !process.Equal(communicatedProcess) {
					continue
				}
				for _, socket := range communication.Sockets {
					if socket.IsMatched(targetSocket) {
						return true
					}
				}
			}
		}
	}
	return false
}
