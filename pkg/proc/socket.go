package proc

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
)

// Socket is information needed to control network.
type Socket struct {
	Protocol              gopacket.LayerType
	LocalIP, RemoteIP     net.IP
	LocalPort, RemotePort uint16
}

func (s *Socket)String() string {
	return fmt.Sprintf("{Protocol:%s LocalIP:%s LocalPort:%d RemoteIP:%s RemortPort:%d}",
		s.Protocol, s.LocalIP, s.LocalPort, s.RemoteIP, s.RemotePort)
}

type direction bool

const (
	in direction = iota%2 == 0
	out
)

type packetIPAddr struct {
	src, dst net.IP
}

// CheckSocketAndCommunicatedContainer returns socket and communicated container from packet and containers.
func CheckSocketAndCommunicatedContainer(packet *gopacket.Packet, containers []*container.Container) (socket *Socket, communicatedContainer *container.Container, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_packet": packet,
		"containers": containers,
	})
	argFields.Debug("trying to check socket and communicated container")

	socket = &Socket{}

	// Check the protocol of network layer
	var ip packetIPAddr
	switch (*packet).NetworkLayer().LayerType() {
	case layers.LayerTypeIPv4:
		networkLayer := (*packet).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ip.src = networkLayer.SrcIP
		ip.dst = networkLayer.DstIP
		socket.Protocol = networkLayer.NextLayerType()
	case layers.LayerTypeIPv6:
		networkLayer := (*packet).Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		ip.src = networkLayer.SrcIP
		ip.dst = networkLayer.DstIP
		socket.Protocol = networkLayer.NextLayerType()
	default:
		err = errors.New("the network layer protocol not supported")
		argFields.WithField("error", err).Debug("failed to check socket and communicated container")
		return
	}

	// Check container and direction, local IP, remote IP
	var packetDirection direction
	setIPOfSocket:
	for _, container := range containers {
		for _, ipAddr := range container.IPAddresses {
			if ip.src.Equal(ipAddr) {
				packetDirection = out
				communicatedContainer = container
				socket.LocalIP, socket.RemoteIP = ip.src, ip.dst
				break setIPOfSocket
			} else if ip.dst.Equal(ipAddr) {
				packetDirection = in
				communicatedContainer = container
				socket.LocalIP, socket.RemoteIP = ip.dst, ip.src
				break setIPOfSocket
			}
		}
	}
	if communicatedContainer == nil {
		err = errors.New("communicated container not found")
		argFields.WithField("error", err).Debug("failed to check socket and communicated container")
		return
	}

	// Check the protocol inside network layer
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

	argFields.WithFields(logrus.Fields{
		"target_socket": socket,
		"communicated_container": communicatedContainer,
		}).Debug("the ppid retrieved")
	return
}

// CheckIdentifierOfICMPv4 returns identifier from icmp packet.
func CheckIdentifierOfICMPv4(packet *gopacket.Packet) (identifier uint16, err error) {
	argFields := logrus.WithField("packet", packet)
	argFields.Debug("trying to check type code and identifier of icmp")

	icmpv4Layer := (*packet).Layer(layers.LayerTypeICMPv4)
	if icmpv4Layer == nil {
		err = errors.New("icmpv4 layer not found")
		argFields.WithField("error", err).Debug("failed to check type code and identifier of icmpv4")
		return
	}

	icmpv4, _ := icmpv4Layer.(*layers.ICMPv4)
	identifier = icmpv4.Id

	argFields.WithFields(logrus.Fields{
		"identifier": identifier,
	}).Debug("checked type code and identifier of icmpv4")
	return
}

// IsSupportProtocol reports whether the protocol is supported.
// func (s *Socket) IsSupportProtocol() bool {
// 	for _, protocol := range supportedProtocol {
// 		if s.Protocol == protocol {
// 			return true
// 		}
// 	}
// 	return false
// }
