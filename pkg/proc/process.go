package proc

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tomo-9925/cnet/pkg/container"
)

// Process is information about process needed to analyze communications of container.
type Process struct {
	ID                int
	Executable, Path  string
}

// Equal reports whether c and x are the same process.
func (p *Process)Equal(x *Process) bool {
	if p.Path != "" && x.Path != "" {
		if p.Path == x.Path {
			return true
		}
		return false
	} else if p.Executable != "" && x.Executable != "" && p.Executable == x.Executable {
		return true
	}
	return false
}

// IdentifyProcessOfContainer returns Process of container from Socket and Container and Packet.
func IdentifyProcessOfContainer(socket *Socket, container *container.Container, packet *gopacket.Packet) (process *Process, err error) {
	switch socket.Protocol {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		var inode uint64
		inode, err = SearchInodeFromNetOfPid(socket, container.Pid)
		if err != nil {
			return
		}
		process, err = SearchProcessOfContainerFromInode(container, inode)
	default:
		return process, errors.New("the protocol not supported")
	}
	return
}

// SearchInodeFromNetOfPid returns inode from net of a specific pid in proc filesystem.
func SearchInodeFromNetOfPid(socket *Socket, pid int) (inode uint64, err error) {
	// Select file path
	var netFilePath string
	switch socket.Protocol {
	case layers.LayerTypeTCP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "tcp")
	case layers.LayerTypeUDP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "udp")
	// NOTE: The raw file does not contain rem_address, so the communicated process cannot be identified when more than one process is communicated with ICMP.
	// case layers.LayerTypeICMPv4:
	// 	netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "raw")
	default:
		return inode, errors.New("file path not defined")
	}

	// Read all file
	var file []byte
	file, err = ioutil.ReadFile(netFilePath)
	if err != nil {
		return
	}

	// Make local_address and rem_address string
	socketLocalPort := fmt.Sprintf("%04X", socket.LocalPort)
	socketRemoteAddr := fmt.Sprintf("%s:%04X", IPtoa(socket.RemoteIP), socket.RemotePort)

	// Search entry of net  socket
	entryScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	entryScanner.Scan() // Skip header line
	for entryScanner.Scan() {
		columnScanner := bufio.NewScanner(strings.NewReader(entryScanner.Text()))
		columnScanner.Split(bufio.ScanWords)
		var remoteAddr string
		checkColumn:
		for columnCounter := 0; columnScanner.Scan(); columnCounter++ {
			switch columnCounter {
			case 1:
				if !strings.HasSuffix(columnScanner.Text(), socketLocalPort) {
					break checkColumn
				}
			case 2:
				remoteAddr = columnScanner.Text()
			case 9:
				if strings.HasSuffix(remoteAddr, "0000") {
					inode, err = strconv.ParseUint(columnScanner.Text(), 10, 64)
					if err != nil {
						return
					}
				} else if remoteAddr == socketRemoteAddr {
					inode, err = strconv.ParseUint(columnScanner.Text(), 10, 64)
					return
				}
				break checkColumn
			}
		}
	}
	if inode != 0 {
		return
	}
	return inode, errors.New("inode not found")
}

// SearchProcessOfContainerFromInode gets inode from net of a specific pid in proc filesystem.
func SearchProcessOfContainerFromInode(container *container.Container, inode uint64) (process *Process, err error) {
	// Make pidStack
	// NOTE: Avoid the use of recursive functions and do a depth-first search for processes with inodes.
	var containerdShimPid int
	containerdShimPid, err = RetrievePPID(container.Pid)
	if err != nil {
		return
	}
	var childPIDs []int
	childPIDs, err = RetrieveChildPIDs(containerdShimPid)
	if err != nil {
		return
	}
	var pids pidStack
	pids.Push(childPIDs...)

	// Check inode of pids
	for pids.Len() != 0 {
		pid := pids.Pop()
		if SocketInodeExists(pid, inode) {
			var executable, path string
			executable, err = RetrieveProcessName(pid)
			if err != nil {
				return
			}
			path, err = RetrieveProcessPath(pid)
			if err != nil {
				return
			}
			return &Process{pid, executable, path}, err
		}
		childPIDs, err = RetrieveChildPIDs(pid)
		if err != nil {
			return
		}
		pids.Push(childPIDs...)
	}
	return process, errors.New("process not found")
}

// RetrievePPID gets the PPID from stat of proc filesystem.
func RetrievePPID(pid int) (ppid int, err error) {
	var file []byte
	file, err = ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "stat"))
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	for i := 0; scanner.Scan(); i++ {
		if i == 3 {
			ppid, err = strconv.Atoi(scanner.Text())
			break
		}
	}
	return
}

// RetrieveChildPIDs gets child PIDs from children of proc filesystem.
func RetrieveChildPIDs(pid int) (childPIDs []int, err error) {
	pidStr := strconv.Itoa(pid)
	netFilePath := filepath.Join(procPath, pidStr, "task", pidStr, "children")
	var file []byte
	file, err = ioutil.ReadFile(netFilePath)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		pid, err = strconv.Atoi(scanner.Text())
		if err != nil {
			return
		}
		childPIDs = append(childPIDs, pid)
	}
	return
}

// SocketInodeExists reports whether the process has socket inode.
func SocketInodeExists(pid int, inode uint64) bool {
	inodeStr := strconv.FormatUint(inode, 10)
	fdDirPath := filepath.Join(procPath, strconv.Itoa(pid), "fd")
	fdFiles, err := ioutil.ReadDir(fdDirPath)
	if err != nil {
			return false
	}
	for _, fdFile := range fdFiles {
		linkContent, err := os.Readlink(filepath.Join(fdDirPath, fdFile.Name()))
		if err != nil {
			return false
		}
		if !strings.HasPrefix(linkContent, "socket") {
			continue
		}
		if linkContent[8:len(linkContent)-1] == inodeStr {
			return true
		}
	}
	return false
}

// RetrieveProcessName gets the process name from stat of proc filesystem.
func RetrieveProcessName(pid int) (executable string, err error) {
	var commFile []byte
	commFile, err = ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "comm"))
	if err != nil {
		return
	}
	executable = strings.TrimSuffix(*(*string)(unsafe.Pointer(&commFile)), "\n")
	return
}

// RetrieveProcessPath gets the process path from stat of proc filesystem.
func RetrieveProcessPath(pid int) (path string, err error) {
	path, err = os.Readlink(filepath.Join(procPath, strconv.Itoa(pid), "exe"))
	return
}
