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

// CheckSocketAndCommunicatedContainer returns socket and communicated container from packet and containers.
func CheckSocketAndCommunicatedContainer(packet *gopacket.Packet, containers []*container.Container) (*Socket, *container.Container, error) {
	var pSocket Socket
	var pContainer *container.Container
	var pDirection direction

	// Check the protocol of network layer
	// This program only supports IPv4
	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, nil, errors.New("Packet not contained IPv4 layer")
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Check container and direction, local IP, remote IP
	for _, container := range containers {
		if ip.SrcIP.Equal(container.IP) {
			pDirection = out
			pContainer = container
			pSocket.LocalIP, pSocket.RemoteIP = ip.SrcIP, ip.DstIP
			break
		} else if ip.DstIP.Equal(container.IP) {
			pDirection = in
			pContainer = container
			pSocket.LocalIP, pSocket.RemoteIP = ip.DstIP, ip.SrcIP
			break
		}
	}
	if pContainer == nil {
		return nil, nil, errors.New("Source of communication not identified")
	}

	// Check the protocol inside network layer
	pSocket.Protocol = ip.NextLayerType()
	switch pSocket.Protocol {
	case layers.LayerTypeTCP:
		tcp, _ := (*packet).Layer(layers.LayerTypeTCP).(*layers.TCP)
		switch pDirection {
		case out:
			pSocket.LocalPort, pSocket.RemotePort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		case in:
			pSocket.LocalPort, pSocket.RemotePort = uint16(tcp.DstPort), uint16(tcp.SrcPort)
		}
	case layers.LayerTypeUDP:
		udp, _ := (*packet).Layer(layers.LayerTypeUDP).(*layers.UDP)
		switch pDirection {
		case out:
			pSocket.LocalPort, pSocket.RemotePort = uint16(udp.SrcPort), uint16(udp.DstPort)
		case in:
			pSocket.LocalPort, pSocket.RemotePort = uint16(udp.DstPort), uint16(udp.SrcPort)
		}
	}

	return &pSocket, pContainer, nil
}

// IsSupportProtocol reports whether the protocol is supported.
func (s *Socket) IsSupportProtocol() bool {
	switch s.Protocol {
	case layers.LayerTypeTCP:
		return true
	case layers.LayerTypeUDP:
		return true
	// Note: ICMP packets containing identifer may be able to support.
	// case layers.LayerTypeICMPv4:
	// 	return true
	default:
		return false
	}
}
