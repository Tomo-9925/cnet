package container

import "net"

// Container is information about container needed to analyze communications of container.
type Container struct {
	ID   string
	IP   net.IP
	Name string
	Pid  int // ID of container's main running process
}
