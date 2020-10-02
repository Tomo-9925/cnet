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
	Executable string
	Path       string
	Pid        int
	Inode      uint64
}

// IdentifyProcessOfContainer returns Process of container from Socket and Container and Packet.
func IdentifyProcessOfContainer(targetSocket *Socket, targetContainer *container.Container, packet *gopacket.Packet) (*Process, error) {
	var targetProcess *Process

	switch targetSocket.Protocol {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		inode, err := SearchInodeFromNetOfPid(targetSocket, targetContainer.Pid)
		if err != nil {
			return nil, err
		}
		targetProcess, err = SearchProcessOfContainerFromInode(targetContainer, inode)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("the protocol not supported")
	}

	return targetProcess, nil
}

// SearchInodeFromNetOfPid returns inode from net of a specific pid in proc filesystem.
func SearchInodeFromNetOfPid(targetSocket *Socket, pid int) (uint64, error) {
	// Select file path
	netFilePath := ""
	switch targetSocket.Protocol {
	case layers.LayerTypeTCP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "tcp")
	case layers.LayerTypeUDP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "udp")
	// case layers.LayerTypeICMPv4:
	// 	netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "raw")
	default:
		return 0, errors.New("file path not defined")
	}

	// Read all file
	file, err := ioutil.ReadFile(netFilePath)
	if err != nil {
		return 0, err
	}

	// Make local_address and rem_address string
	// Assume a little endian
	socketLocalPort := fmt.Sprintf("%04X", targetSocket.LocalPort)
	socketRemoteAddr := fmt.Sprintf("%s:%04X", IPtoa(targetSocket.RemoteIP), targetSocket.RemotePort)

	// Search entry of net  targetSocket
	var inode uint64
	entryScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	entryScanner.Scan() // Skip header line
	for entryScanner.Scan() {
		columnScanner := bufio.NewScanner(strings.NewReader(entryScanner.Text()))
		columnScanner.Split(bufio.ScanWords)
		remoteAddr := ""
		for columnCounter := 0; columnScanner.Scan(); columnCounter++ {
			switch columnCounter {
			case 1:
				if !strings.HasSuffix(columnScanner.Text(), socketLocalPort) {
					break
				}
			case 2:
				remoteAddr = columnScanner.Text()
			case 9:
				inode, err = strconv.ParseUint(columnScanner.Text(), 10, 64)
				if err != nil {
					return 0, err
				}
				if remoteAddr == socketRemoteAddr {
					return inode, err
				}
				break
			}
		}
	}

	return inode, nil
}

// SearchProcessOfContainerFromInode gets inode from net of a specific pid in proc filesystem.
func SearchProcessOfContainerFromInode(targetContainer *container.Container, inode uint64) (*Process, error) {
	// Make pidStack
	// NOTE: Avoid recursive function
	containerdShimPid, err := GetPPID(targetContainer.Pid)
	if err != nil {
		return nil, err
	}
	childrenPIDs, err := GetChildrenPIDs(containerdShimPid)
	var pids pidStack
	pids.Push(childrenPIDs...)

	// Check inode of pids
	inodeStr := strconv.FormatUint(inode, 10)
	for pids.Len() != 0 {
		pid := pids.Pop()
		processDirPath := filepath.Join(procPath, strconv.Itoa(pid))
		fdDirPath := filepath.Join(processDirPath, "fd")
		fdFiles, err := ioutil.ReadDir(fdDirPath)

		for _, fdFile := range fdFiles {
			fdFilePath := filepath.Join(fdDirPath, fdFile.Name())
			linkContent, err := os.Readlink(fdFilePath)
			if err != nil {
				return nil, err
			} else if strings.Contains(linkContent, inodeStr) {
				commPath := filepath.Join(processDirPath, "comm")
				commFile, err := ioutil.ReadFile(commPath)
				if err != nil {
					return nil, err
				}
				exePath := filepath.Join(processDirPath, "exe")
				processPath, err := os.Readlink(exePath)
				if err != nil {
					return nil, err
				}
				return &Process{
					Executable: strings.TrimSuffix(*(*string)(unsafe.Pointer(&commFile)), "\n"),
					Path:       processPath,
					Pid:        pid,
					Inode:      inode,
				}, nil
			}
		}

		childrenPIDs, err = GetChildrenPIDs(pid)
		if err != nil {
			return nil, err
		}
		pids.Push(childrenPIDs...)
	}

	return nil, errors.New("process not found")
}

// GetPPID gets the PPID from stat of proc filesystem.
func GetPPID(pid int) (int, error) {
	netFilePath := filepath.Join(procPath, strconv.Itoa(pid), "stat")
	file, err := ioutil.ReadFile(netFilePath)
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)

	for i := 0; scanner.Scan(); i++ {
		if i == 3 {
			return strconv.Atoi(scanner.Text())
		}
	}

	return 0, errors.New("the stat file not scanned")
}

// GetChildrenPIDs gets children PIDs from children of proc filesystem.
func GetChildrenPIDs(pid int) ([]int, error) {
	pidStr := strconv.Itoa(pid)
	netFilePath := filepath.Join(procPath, pidStr, "task", pidStr, "children")
	file, err := ioutil.ReadFile(netFilePath)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	var childrenPIDs []int
	for scanner.Scan() {
		pid, err := strconv.Atoi(scanner.Text())
		if err != nil {
			return nil, err
		}
		childrenPIDs = append(childrenPIDs, pid)
	}

	return childrenPIDs, nil
}
