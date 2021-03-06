package policy

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
	"github.com/tomo-9925/cnet/pkg/docker"
	"github.com/tomo-9925/cnet/pkg/proc"
)

// Policy is information about the communication of container needed to analyze communications of container.
type Policy struct {
	Container      *container.Container
	Communications []*Communication
}

func (p *Policy)String() string {
	return fmt.Sprintf("{Container:%s Communications:%v}", p.Container, p.Communications)
}

// Communication is information about process and socket needed to analyze communications of container.
type Communication struct {
	Processes []*proc.Process
	Sockets   []*Socket
}

func (c *Communication)String() string {
	return fmt.Sprintf("{Processes:%v Sockets:%v}", c.Processes, c.Sockets)
}

// Socket is information about information needed to control network.
type Socket struct {
	Protocol              gopacket.LayerType
	RemoteIP              *net.IPNet
	LocalPort, RemotePort uint16
}

func (s *Socket)String() string {
	return fmt.Sprintf("{Protocol:%s RemoteIP:%s LocalPort:%d RemotePort:%d}", s.Protocol, s.RemoteIP, s.LocalPort, s.RemotePort)
}

// IsMatched reports whether content of the proc.Socket matches policy.Socket.
func (s *Socket) IsMatched(x *proc.Socket) bool {
	if s.Protocol != x.Protocol {
		return false
	} else if s.LocalPort != 0 && s.LocalPort != x.LocalPort {
		return false
	} else if s.RemotePort != 0 && s.RemotePort != x.RemotePort {
		return false
	} else if s.RemoteIP != nil && !s.RemoteIP.Contains(x.RemoteIP) {
		return false
	}
	return true
}

// Policies is the structure that have list of Policy and mutex
type Policies struct {
	Path    string
	List    []*Policy
	RWMutex sync.RWMutex
}

func (p *Policies)String() string {
	return fmt.Sprint(p.List)
}

// Reload retrieve the policy list of the specified YAML file path again.
func (p *Policies)Reload() (err error) {
	pathField := logrus.WithFields(logrus.Fields{
		"policies": p.List,
		"path": p.Path,
	})
	pathField.Debug("trying to reload the policy")

	var parsedPolicyList []*Policy
	parsedPolicyList, err = parseYAMLPolicyList(p.Path)
	if err != nil {
		pathField.WithField("error", err).Debug("failed to reload the policy")
		return
	}
	p.RWMutex.Lock()
	p.List = parsedPolicyList
	p.RWMutex.Unlock()

	pathField.Debug("the policy reloaded")
	return
}

// IsDefined reports whether the policy is defined.
func (p *Policies) IsDefined(communicatedContainer *container.Container, communicatedProcess *proc.Process, targetSocket *proc.Socket) (judgement bool) { ////nolint:gocognit
	relevantFields := logrus.WithFields(logrus.Fields{
		"policies": p,
		"communicated_container": communicatedContainer,
		"communicated_process": communicatedProcess,
		"target_socket": targetSocket,
	})
	relevantFields.Debug("checking whether define the communication in this policies")

	if cacheRawData, exist := PolicyCache.Get(GenerateHash(communicatedContainer,communicatedProcess,targetSocket)); exist {
		judgement = cacheRawData.(bool)
		relevantFields.WithField("judgement", judgement).Debug("checked whether define the communication in this policies")
		return
	}

	if targetSocket.Protocol == layers.LayerTypeUDP && targetSocket.RemotePort == 53 {
		dockerdPath, err := proc.RetrieveProcessPath(docker.PID)
		if err == nil && communicatedProcess.Path == dockerdPath {
			relevantFields.Debug("the dns request is assumed to be defined")
			return true
		}
	}

	// HACK: So many indents that it's hard to understand. The structure of Policies may need to be rethought.
	p.RWMutex.RLock()
	comparePolicy:
	for _, policy := range p.List {
		if !policy.Container.Equal(communicatedContainer) {
			continue
		}
		logrus.WithFields(logrus.Fields{
			"policy_container": policy.Container,
			"communicated_container": communicatedContainer,
		}).Trace("the relevant container found")
		for _, communication := range policy.Communications {
			for _, policyProcess := range communication.Processes {
				if !policyProcess.Equal(communicatedProcess) {
					continue
				}
				logrus.WithFields(logrus.Fields{
					"policy_process": policyProcess,
					"communicated_process": communicatedProcess,
				}).Trace("the relevant process found")
				for _, policySocket := range communication.Sockets {
					if policySocket.IsMatched(targetSocket) {
						logrus.WithFields(logrus.Fields{
							"policy_socket": policySocket,
							"targetSocket": targetSocket,
						}).Trace("the relevant socket found")
						relevantFields.Debug("the communication defined")
						judgement = true
						break comparePolicy
					}
				}
			}
		}
	}
	p.RWMutex.RUnlock()

	PolicyCache.Set(GenerateHash(communicatedContainer,communicatedProcess,targetSocket), judgement,0)
	relevantFields.WithField("judgement", judgement).Debug("checked whether define the communication in this policies")
	return
}
