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

// NOTE: ICMP packets containing identifier may be able to support.
// var supportedProtocol []gopacket.LayerType = []gopacket.LayerType{
// 	layers.LayerTypeTCP,
// 	layers.LayerTypeUDP,
// }

// CheckSocketAndCommunicatedContainer returns socket and communicated container from packet and containers.
func CheckSocketAndCommunicatedContainer(packet *gopacket.Packet, containers []*container.Container) (socket *Socket, communicatedContainer *container.Container, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_packet": packet,
		"containers": containers,
	})
	argFields.Debug("trying to check socket and communicated container")

	// Check the protocol of network layer
	// This program only supports IPv4
	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		err = errors.New("packet not contained ipv4 layer")
		argFields.WithField("error", err).Debug("failed to check socket and communicated container")
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Check container and direction, local IP, remote IP
	var packetDirection direction
	for _, container := range containers {
		for _, ipAddr := range container.IPAddresses {
			if ip.SrcIP.Equal(ipAddr) {
				packetDirection = out
				communicatedContainer = container
				socket = &Socket{LocalIP: ip.SrcIP, RemoteIP: ip.DstIP}
				break
			} else if ip.DstIP.Equal(ipAddr) {
				packetDirection = in
				communicatedContainer = container
				socket = &Socket{LocalIP: ip.DstIP, RemoteIP: ip.SrcIP}
				break
			}
		}
	}
	if communicatedContainer == nil {
		err = errors.New("communicated container not found")
		argFields.WithField("error", err).Debug("failed to check socket and communicated container")
		return
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

	argFields.WithFields(logrus.Fields{
		"target_socket": socket,
		"communicated_container": communicatedContainer,
		}).Debug("the ppid retrieved")
	return
}

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
