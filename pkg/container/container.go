package container

import (
	"net"
	"strings"
)

// Container is information about container needed to analyze communications of container.
type Container struct {
	ID   string
	IP   net.IP
	Name string
	Pid  int // ID of container's main running process
}

// Equal reports whether c and x are the same container.
func (c *Container) Equal(x *Container) bool {
	if c.ID != "" && x.ID != "" {
		if strings.HasPrefix(c.ID, x.ID) || strings.HasPrefix(c.ID, x.ID) {
			return true
		}
		return false
	} else if c.Name == "" || x.Name == "" {
		return false
	}
	// NOTE: Container names got from the Docker Engine API may have a slash at the beginning.
	hasSlash := [2]bool{c.Name[0]=='/', x.Name[0]=='/'}
	if hasSlash[0] == hasSlash[1] {
		return c.Name == x.Name
	} else if hasSlash[0] == true {
		return c.Name[1:] == x.Name
	}
	return c.Name == x.Name[1:]
}
