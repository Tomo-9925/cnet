package proc

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/docker"
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

func (s *Socket)Hash() string {
	return fmt.Sprintf("%X%X%X%X%X", s.Protocol, s.LocalIP, s.RemoteIP, s.LocalPort, s.RemotePort)
}

type direction bool

const (
	in direction = iota%2 == 0
	out
)

type packetIPAddr struct {
	src, dst net.IP
}

// CheckSocketAndCommunicatedDockerContainer returns socket and communicated docker container from packet and containers.
func CheckSocketAndCommunicatedDockerContainer(packet *gopacket.Packet, containers *docker.Containers) (socket *Socket, communicatedContainer *container.Container, err error) {
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
	containers.RWMutex.RLock()
	setIPOfSocket:
	for _, container := range containers.List {
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
	containers.RWMutex.RUnlock()
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
		}).Debug("socket and communicated container checked")
	return
}

// CheckIdentifierOfICMP returns identifier from icmp packet.
func CheckIdentifierOfICMP(socket *Socket, packet *gopacket.Packet) (identifier uint16, err error) {
	argFields := logrus.WithField("packet", packet)
	argFields.Debug("trying to identifier of the icmp packet")

	switch socket.Protocol {
	case layers.LayerTypeICMPv4:
		icmpv4, _ := (*packet).Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		// FIXME: Limiting to ICMP types with Identifier will not work correctly.
		// switch icmpv4.TypeCode {
		// case layers.ICMPv4TypeEchoRequest, layers.ICMPv4TypeEchoReply,
		// layers.ICMPv4TypeTimestampRequest, layers.ICMPv4TypeTimestampReply,
		// layers.ICMPv4TypeAddressMaskRequest, layers.ICMPv4TypeAddressMaskReply:
		identifier = icmpv4.Id
		// default:
		// 	err = errors.New("identifier not found")
		// }
	case layers.LayerTypeICMPv6:
		icmpv6, _ := (*packet).Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		icmpv6Type := icmpv6.NextLayerType()
		if icmpv6Type != layers.LayerTypeICMPv6Echo {
			err = errors.New("identifier not found")
			break
		}
		icmpv6Echo, _ := (*packet).Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
		identifier = icmpv6Echo.Identifier
	default:
		err = errors.New("this packet is not icmp protocol")
	}

	if err != nil {
		argFields.WithField("error", err).Debug("failed to check type code and identifier of icmp")
	} else {
		argFields.WithFields(logrus.Fields{
			"identifier": identifier,
		}).Debug("identifier of the icmp packet found")
	}
	return
}
