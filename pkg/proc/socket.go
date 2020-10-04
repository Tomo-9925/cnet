package proc

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tomo-9925/cnet/pkg/container"
)

// Socket is information needed to control network.
type Socket struct {
	Protocol   gopacket.LayerType
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  uint16
	RemotePort uint16
}

type direction bool

const (
	in direction = iota%2 == 0
	out
)

// NOTE: ICMP packets containing identifer may be able to support.
var supportedProtocol []gopacket.LayerType = []gopacket.LayerType{
	layers.LayerTypeTCP,
	layers.LayerTypeUDP,
}

// CheckSocketAndCommunicatedContainer returns socket and communicated container from packet and containers.
func CheckSocketAndCommunicatedContainer(packet *gopacket.Packet, containers []*container.Container) (socket *Socket, communicatedContainer *container.Container, err error) {
	// Check the protocol of network layer
	// This program only supports IPv4
	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return socket, communicatedContainer, errors.New("packet not contained ipv4 layer")
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Check container and direction, local IP, remote IP
	var packetDirection direction
	for _, container := range containers {
		if ip.SrcIP.Equal(container.IP) {
			packetDirection = out
			communicatedContainer = container
			socket = &Socket{LocalIP: ip.SrcIP, RemoteIP: ip.DstIP}
			break
		} else if ip.DstIP.Equal(container.IP) {
			packetDirection = in
			communicatedContainer = container
			socket = &Socket{LocalIP: ip.DstIP, RemoteIP: ip.SrcIP}
			break
		}
	}
	if communicatedContainer == nil {
		return socket, communicatedContainer, errors.New("communicated container not found")
	}


	// Check the protocol inside network layer
	socket.Protocol = ip.NextLayerType()
	switch socket.Protocol {
	case layers.LayerTypeTCP:
		tcp, _ := (*packet).Layer(layers.LayerTypeTCP).(*layers.TCP)
		switch packetDirection {
		case out:
			socket.LocalPort, socket.RemotePort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		case in:
			socket.LocalPort, socket.RemotePort = uint16(tcp.DstPort), uint16(tcp.SrcPort)
		}
	case layers.LayerTypeUDP:
		udp, _ := (*packet).Layer(layers.LayerTypeUDP).(*layers.UDP)
		switch packetDirection {
		case out:
			socket.LocalPort, socket.RemotePort = uint16(udp.SrcPort), uint16(udp.DstPort)
		case in:
			socket.LocalPort, socket.RemotePort = uint16(udp.DstPort), uint16(udp.SrcPort)
		}
	}
	return
}

// IsSupportProtocol reports whether the protocol is supported.
func (s *Socket) IsSupportProtocol() bool {
	for _, protocol := range supportedProtocol {
		if s.Protocol == protocol {
			return true
		}
	}
	return false
}
