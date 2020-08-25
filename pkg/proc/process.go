package proc

import "github.com/tomo-9925/cnet/pkg/container"

// Process is information about process needed to analyze communications of container.
type Process struct {
	Executable string
	Path       string
	Pid        int
	Inode      uint64
}

// IdentifyProcessOfContainer returns Process of container and the Container from Socket.
func IdentifyProcessOfContainer(pSocket *Socket, containers []*container.Container) (*Process, *container.Container, error)
