package proc

import (
	"net"

	"github.com/google/gopacket"
)

// Socket is information needed to control network.
type Socket struct {
	Protocol   gopacket.LayerType
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
}

// PtoS converts gopacket.Packet into Socket.
func PtoS(packet *gopacket.Packet) *Socket

// IsSupportProtocol reports whether the protocol is supported.
func (s *Socket) IsSupportProtocol() bool
