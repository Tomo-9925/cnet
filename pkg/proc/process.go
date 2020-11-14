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
	"github.com/sirupsen/logrus"
	"github.com/tomo-9925/cnet/pkg/container"
)

// Process is information about process needed to analyze communications of container.
type Process struct {
	ID               int
	Executable, Path string
}

func (p *Process)String() string {
	return fmt.Sprintf("{ID:%d Executable:%s Path:%s}", p.ID, p.Executable, p.Path)
}

// Equal reports whether c and x are the same process.
func (p *Process)Equal(x *Process) bool {
	if p.Path != "" && x.Path != "" && p.Path == x.Path {
		return true
	} else if p.Executable != "" && x.Executable != "" && p.Executable == x.Executable {
		return true
	}
	return false
}

// IdentifyProcessOfContainer returns Process of container from Socket and Container and Packet.
func IdentifyProcessOfContainer(socket *Socket, container *container.Container, packet *gopacket.Packet) (process *Process, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_socket": socket,
		"communicated_container": container,
		// "packet": packet,
	})
	argFields.Debug("trying to identify process of container")

	switch socket.Protocol {
	case layers.LayerTypeTCP, layers.LayerTypeUDP:
		var inode uint64
		inode, err = SearchInodeFromNetOfPid(socket, container.Pid)
		if err != nil {
			argFields.WithField("error", err).Debug("failed to indentify process of container")
			return
		}
		process, err = SearchProcessOfContainerFromInode(container, inode)
		if err != nil {
			argFields.WithField("error", err).Debug("failed to indentify process of container")
		}
		argFields.WithField("identified_process", process).Debug("the process identified")
		return
	}

	err = errors.New("the protocol not supported")
	argFields.WithField("error", err).Debug("failed to indentify process of container")
	return
}

// SearchInodeFromNetOfPid returns inode from net of a specific pid in proc filesystem.
func SearchInodeFromNetOfPid(socket *Socket, pid int) (inode uint64, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_socket": socket,
		"pid": pid,
	})
	argFields.Debug("trying to search inode from net of pid")

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
		err = errors.New("file path not defined")
		argFields.WithField("error", err).Debug("failed to search inode from net of pid")
		return
	}

	var file []byte
	file, err = ioutil.ReadFile(netFilePath)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to search inode from net of pid")
		return
	}

	// Make local_address and rem_address string
	socketLocalPort := fmt.Sprintf("%04X", socket.LocalPort)
	socketRemoteAddr := fmt.Sprintf("%s:%04X", IPtoa(socket.RemoteIP), socket.RemotePort)
	argFields.WithFields(logrus.Fields{
		"socket_local_port_string": socketLocalPort,
		"socket_remote_address_string": socketRemoteAddr,
		}).Trace("the strings for comparison created")

	// Search entry of net  socket
	entryScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	entryScanner.Scan() // Skip header line
	for entryScanner.Scan() {
		argFields.WithField("entry", entryScanner.Text()).Trace("checking the entry")
		columnScanner := bufio.NewScanner(strings.NewReader(entryScanner.Text()))
		columnScanner.Split(bufio.ScanWords)
		var remoteAddr string
	checkColumn:
		for columnCounter := 0; columnScanner.Scan(); columnCounter++ {
			switch columnCounter {
			case localAddressColumn:
				if !strings.HasSuffix(columnScanner.Text(), socketLocalPort) {
					argFields.WithField("net_local_port", columnScanner.Text()).Trace("the entry skipped")
					break checkColumn
				}
			case remoteAddressColumn:
				remoteAddr = columnScanner.Text()
				argFields.WithField("net_remote_port", remoteAddr).Trace("remote addr scanned")
			case inodeColumn:
				if strings.HasSuffix(remoteAddr, "0000") || remoteAddr == socketRemoteAddr {
					inode, err = strconv.ParseUint(columnScanner.Text(), 10, 64)
					argFields.WithField("socket_inode", inode).Debug("exact matched inode found")
					return
				}
				break checkColumn
			}
		}
	}
	err = errors.New("inode not found")
	argFields.WithField("error", err).Debug("failed to search inode from net of pid")
	return
}

// SearchProcessOfContainerFromInode gets inode from net of a specific pid in proc filesystem.
func SearchProcessOfContainerFromInode(container *container.Container, inode uint64) (process *Process, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"communicated_container": container,
		"socket_inode": inode,
	})
	argFields.Debug("trying to search process of container from inode")

	// Make pidStack
	// NOTE: Avoid the use of recursive functions and do a depth-first search for processes with inodes.
	var containerdShimPid int
	containerdShimPid, err = RetrievePPID(container.Pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to search process of container from inode")
		return
	}
	argFields.WithField("pid_of_containerd_shim", containerdShimPid).Trace("pid of containered-shim retrieved")
	var childPIDs []int
	childPIDs, err = RetrieveChildPIDs(containerdShimPid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to search process of container from inode")
		return
	}
	argFields.WithField("child_pids_of_containerd_shim", childPIDs).Trace("child pids of containered-shim retrieved")
	var pids pidStack
	pids.Push(childPIDs...)

	// Check inode of pids
	for pids.Len() != 0 {
		pid := pids.Pop()
		argFields.WithField("poped_pid", pid).Trace("pid poped from pid stack")
		if SocketInodeExists(pid, inode) {
			var executable, path string
			executable, err = RetrieveProcessName(pid)
			if err != nil {
				argFields.WithField("error", err).Debug("failed to search process of container from inode")
				return
			}
			argFields.WithField("retrieved_executable", executable).Trace("executable retrieved")
			path, err = RetrieveProcessPath(pid)
			if err != nil {
				argFields.WithField("error", err).Debug("failed to search process of container from inode")
				return
			}
			argFields.WithField("retrieved_path", path).Trace("path retrieved")
			process = &Process{pid, executable, path}
			return
		}
		childPIDs, err = RetrieveChildPIDs(pid)
		if err != nil {
			argFields.WithField("error", err).Debug("failed to search process of container from inode")
			return
		}
		argFields.WithField("retrieved_child_pids", childPIDs).Trace("child_pids retrieved")
		pids.Push(childPIDs...)
	}
	err = errors.New("process not found")
	argFields.WithField("error", err).Debug("failed to search process of container from inode")
	return
}

// RetrievePPID gets the PPID from stat of proc filesystem.
func RetrievePPID(pid int) (ppid int, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve ppid")

	var file []byte
	file, err = ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "stat"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve ppid")
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
	argFields.WithField("retrieved_ppid", ppid).Debug("the ppid retrieved")
	return
}

// RetrieveChildPIDs gets child PIDs from children of proc filesystem.
func RetrieveChildPIDs(pid int) (childPIDs []int, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve child pids")

	pidStr := strconv.Itoa(pid)
	netFilePath := filepath.Join(procPath, pidStr, "task", pidStr, "children")
	var file []byte
	file, err = ioutil.ReadFile(netFilePath)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve child pids")
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		pid, err = strconv.Atoi(scanner.Text())
		if err != nil {
			argFields.WithField("error", err).Debug("failed to retrieve child pids")
			return
		}
		argFields.WithField("retrieved_child_pid", pid).Trace("child pid retrieved")
		childPIDs = append(childPIDs, pid)
	}
	argFields.WithField("retrieved_child_pids", childPIDs).Debug("the child pids retrieved")
	return
}

// SocketInodeExists reports whether the process has socket inode.
func SocketInodeExists(pid int, inode uint64) bool {
	argFields := logrus.WithFields(logrus.Fields{
		"pid": pid,
		"socket_inode": inode,
	})
	argFields.Debug("trying to check whether the process has socket inode")

	inodeStr := strconv.FormatUint(inode, 10)
	fdDirPath := filepath.Join(procPath, strconv.Itoa(pid), "fd")
	fdFiles, err := ioutil.ReadDir(fdDirPath)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to check whether the process has socket inode")
		return false
	}
	for _, fdFile := range fdFiles {
		linkContent, err := os.Readlink(filepath.Join(fdDirPath, fdFile.Name()))
		if err != nil {
			argFields.WithField("error", err).Debug("failed to check whether the process has socket inode")
			return false
		}
		if !strings.HasPrefix(linkContent, "socket") {
			continue
		}
		if linkContent[8:len(linkContent)-1] == inodeStr {
			return true
		}
	}
	argFields.WithField("error", "file descriptor with the socket inode not found").Debug("failed to check whether the process has socket inode")
	return false
}

// RetrieveProcessName gets the process name from stat of proc filesystem.
func RetrieveProcessName(pid int) (executable string, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve process name")

	var commFile []byte
	commFile, err = ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "comm"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve process name")
		return
	}
	executable = strings.TrimSuffix(*(*string)(unsafe.Pointer(&commFile)), "\n")
	argFields.WithField("executable", executable).Debug("the process name retrieved")
	return
}

// RetrieveProcessPath gets the process path from stat of proc filesystem.
func RetrieveProcessPath(pid int) (path string, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to retrieve process path")
	path, err = os.Readlink(filepath.Join(procPath, strconv.Itoa(pid), "exe"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve process path")
		return
	}
	argFields.Debug("the process path retrieved")
	return
}
