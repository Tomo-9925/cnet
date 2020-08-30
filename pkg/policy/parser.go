package policy

import (
	"errors"
	"io/ioutil"
	"net"
	"strings"

	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/proc"
	"gopkg.in/yaml.v2"
)

// ParseSecurityPolicy returns the information slice of policy.
func ParseSecurityPolicy(path string, containers []*container.Container) (Policies, error) {
	// Open yaml file
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sp := make(map[string]interface{})
	err = yaml.Unmarshal(buf, &sp)
	if err != nil {
		return nil, err
	}

	var policies Policies

	// Parse policies
	if _, exist := sp["policies"]; !exist {
		return nil, errors.New("Policies not found")
	} else if spPolicies, ok := sp["policies"].([]interface{}); !ok {
		return nil, errors.New("Policies not parsed as slice of policy")
	} else {
		for i, spPolicyInterface := range spPolicies {
			spPolicy, ok := spPolicyInterface.(map[string]interface{})
			logrus.Debugln("Policy", i, ":")
			if !ok {
				return nil, errors.New("Policy not parsed")
			}
			policy, err := parsePolicy(spPolicy, containers)
			if err != nil {
				return nil, err
			}
			policies = append(policies, policy)
		}
	}

	logrus.WithField("policies", policies).Debug("policies parsed")
	return policies, nil
}

func parsePolicy(spPolicy map[string]interface{}, containers []*container.Container) (*Policy, error) {
	var policy Policy

	// Parse container
	if _, exist := spPolicy["container"]; !exist {
		return nil, errors.New("Container not found")
	}
	spContainer, ok := spPolicy["container"].(map[string]interface{})
	if !ok {
		return nil, errors.New("Container not parsed as Container")
	}
	container, err := parseContainer(spContainer, containers)
	if err != nil {
		return nil, err
	}
	policy.Container = container
	logrus.WithField("container", container).Debug("container parsed")

	// Parse communications
	if _, exist := spPolicy["communications"]; !exist {
		return &policy, errors.New("Communications not found")
	} else if spCommunications, ok := spPolicy["communications"].([]interface{}); !ok {
		return &policy, errors.New("Communications not parsed as slice of communication")
	} else {
		var communications []*Communication
		for i, spCommunicationInterface := range spCommunications {
			var communication *Communication
			logrus.Debugln("Communication", i, ":")
			spCommunication, ok := spCommunicationInterface.(map[string]interface{})
			if !ok {
				return &policy, errors.New("Communication not parsed")
			}
			communication, err = parseCommunication(spCommunication, containers)
			if err != nil {
				return &policy, err
			}
			communications = append(communications, communication)
			logrus.Debugln("Communications:", communications)
		}
		policy.Communications = communications
	}

	logrus.WithField("policy", policy).Debug("Policy parsed")
	return &policy, nil
}

func parseContainer(spContainer map[string]interface{}, containers []*container.Container) (*container.Container, error) {
	if _, exist := spContainer["name"]; !exist {
		if _, exist := spContainer["id"]; !exist {
			return nil, errors.New("Container name or container id not found")
		}
		ContainerID := spContainer["id"].(string)
		for _, c := range containers {
			if strings.HasPrefix(c.ID, ContainerID) {
				logrus.WithField("container", c).Debug("container found")
				return c, nil
			}
		}
	} else {
		containerName := spContainer["name"].(string)
		for _, c := range containers {
			if c.Name == containerName {
				logrus.WithField("container", c).Debug("container found")
				return c, nil
			}
		}
	}

	return nil, errors.New("Container not found")
}

func parseCommunication(spCommunication map[string]interface{}, containers []*container.Container) (*Communication, error) {
	var communication Communication

	// Parse process
	if _, exist := spCommunication["processes"]; !exist {
		return nil, errors.New("Processes not found")
	} else if spProcesses, ok := spCommunication["processes"].([]interface{}); !ok {
		return nil, errors.New("Processes not parsed as slice of process")
	} else {
		for i, spProcessInterface := range spProcesses {
			spProcess, ok := spProcessInterface.(map[string]interface{})
			logrus.Debugln("Process", i, ":")
			if !ok {
				return nil, errors.New("policy not parsed")
			}
			process, err := parseProcess(spProcess)
			if err != nil {
				return nil, err
			}
			communication.Processes = append(communication.Processes, process)
		}
	}

	// Parse socket
	if _, exist := spCommunication["sockets"]; !exist {
		return nil, errors.New("Socket not found")
	} else if Sockets, ok := spCommunication["sockets"].([]interface{}); !ok {
		return nil, errors.New("Socket not parsed as slice of socket")
	} else {
		for i, spSocketInterface := range Sockets {
			spSocket, ok := spSocketInterface.(map[string]interface{})
			logrus.Debugln("Socket", i, ":")
			if !ok {
				return nil, errors.New("Socket not parsed")
			}
			socket, err := parseSocket(spSocket, containers)
			if err != nil {
				return nil, err
			}
			communication.Sockets = append(communication.Sockets, socket)
		}
	}

	logrus.WithField("communication", communication).Debug("Communication parsed")
	return &communication, nil
}

func parseProcess(spProcess map[string]interface{}) (*proc.Process, error) {
	if _, exist := spProcess["executable"]; exist {
		spExecutable, ok := spProcess["executable"].(string)
		if !ok {
			return nil, errors.New("Executable not parsed as string")
		}
		logrus.WithField("executable", spExecutable).Debug("Executable parsed")
		return &proc.Process{Executable: spExecutable}, nil
	} else if _, exist := spProcess["path"]; exist {
		spPath, ok := spProcess["path"].(string)
		if !ok {
			return nil, errors.New("Path not parsed as string")
		}
		logrus.WithField("path", spPath).Debug("Path parsed")
		return &proc.Process{Path: spPath}, nil
	}

	return nil, errors.New("Process path or process executable not found")
}

func parseSocket(spSocket map[string]interface{}, containers []*container.Container) (*Socket, error) {
	var socket Socket

	// Parse protocol
	if _, exist := spSocket["protocol"]; !exist {
		return nil, errors.New("Protocol not found")
	} else if spProtocol, ok := spSocket["protocol"].(string); !ok {
		return nil, errors.New("Protocol not parsed as string")
	} else if strings.EqualFold(spProtocol, "ICMP") {
		socket.Protocol = layers.LayerTypeICMPv4
	} else if strings.EqualFold(spProtocol, "TCP") {
		socket.Protocol = layers.LayerTypeTCP
	} else if strings.EqualFold(spProtocol, "UDP") {
		socket.Protocol = layers.LayerTypeUDP
	} else {
		return nil, errors.New("Protocol not supported")
	}
	logrus.WithField("protocol", socket.Protocol).Debug("Protocol parsed")

	// Parse remote ip
	if _, exist := spSocket["remote_container"]; exist {
		spRemoteContainer, ok := spSocket["remote_container"].(string)
		if !ok {
			return nil, errors.New("Remote container not parsed as string")
		}
		for _, c := range containers {
			if c.Name == spRemoteContainer {
				socket.RemoteIP.IP = c.IP
				break
			}
		}
	} else if _, exist := spSocket["remote_ip"]; exist {
		if spRemoteIP, ok := spSocket["remote_ip"].(string); !ok {
			return nil, errors.New("RemoteIP not parsed as string")
		} else if strings.Contains(spRemoteIP, "/") {
			_, cidr, err := net.ParseCIDR(spRemoteIP)
			if err != nil {
				return nil, err
			}
			socket.RemoteIP = *cidr
		} else {
			if socket.RemoteIP.IP = net.ParseIP(spRemoteIP); socket.RemoteIP.IP == nil {
				return nil, errors.New("RemoteIP not parsed as IP")
			}
		}
	}
	logrus.WithField("remote_ip", socket.RemoteIP).Debug("RemoteIP parsed")

	// Parse port
	if _, exist := spSocket["local_port"]; exist {
		spLocalPort, ok := spSocket["local_port"].(int)
		if !ok {
			return nil, errors.New("LocalPort not parsed as int")
		}
		socket.LocalPort = uint16(spLocalPort)
		logrus.WithField("local_port", socket.LocalPort).Debug("LocalPort parsed")
	}
	if _, exist := spSocket["remote_port"]; exist {
		spRemotePort, ok := spSocket["remote_port"].(int)
		if !ok {
			return nil, errors.New("RemotePort not parsed as int")
		}
		socket.RemotePort = uint16(spRemotePort)
		logrus.WithField("remote_port", socket.RemotePort).Debug("RemotePort parsed")
	}

	logrus.WithField("socket", socket).Debug("Socket parsed")
	return &socket, nil
}
