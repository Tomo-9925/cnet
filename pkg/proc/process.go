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
	return (p.Path != "" && x.Path != "" && p.Path == x.Path) || ( p.Executable != "" && x.Executable != "" && p.Executable == x.Executable)
}

// IdentifyProcessOfContainer returns Process of container from Socket and Container and Packet.
func IdentifyProcessOfContainer(socket *Socket, container *container.Container, packet *gopacket.Packet) (process *Process, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_socket": socket,
		"communicated_container": container,
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

	// detect the process of raw socket
	var inodes []uint64
	inodes, err = RetrieveAllInodeFromRawOfPid(container.Pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to identify process of container")
		return
	}
	suspiciousProcesses := make(map[Process] struct{})
	for _, inode := range inodes {
		var suspiciousProcess *Process
		suspiciousProcess, err = SearchProcessOfContainerFromInode(container, inode)
		if err != nil {
			argFields.WithField("error", err).Trace("process not found")
			continue
		}
		suspiciousProcesses[*suspiciousProcess] = struct{}{}
	}
	if len(suspiciousProcesses) == 1 {
		for suspiciousProcess := range suspiciousProcesses {
			process = &suspiciousProcess
			argFields.WithField("identified_process", process).Debug("the process identified")
			return
		}
	}
	if socket.Protocol == layers.LayerTypeICMPv4 {
		var identifier uint16
		identifier, err = CheckIdentifierOfICMPv4(packet)
		if err != nil {
			argFields.WithField("error", err).Trace("failed to identify process of container with identifier method")
			return
		}
		identifierStr := strconv.FormatUint(uint64(identifier), 10)
		for suspiciousProcess := range suspiciousProcesses {
			if NSpidExists(suspiciousProcess.ID, identifierStr) {
				process = &suspiciousProcess
				argFields.WithField("identified_process", process).Debug("the process identified")
				return
			}
		}
	}
	for suspiciousProcess := range suspiciousProcesses {
		argFields.WithField("suspicious_process", suspiciousProcess).Info("multiple processes detected")
	}

	err = errors.New("the process not found")
	argFields.WithField("error", err).Debug("failed to indentify process of container")
	return
}

// MakeRetrieveSocketEntryFunction return the function that retrieve socket entry of specific process id and protocol.
func MakeRetrieveSocketEntryFunction(protocol gopacket.LayerType, pid int) (retrieveFunction func() ([3]string, bool), err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"protocol": protocol,
		"pid": pid,
	})
	argFields.Debug("trying to retrieve socket entry")

	var netFilePath string
	switch protocol {
	case layers.LayerTypeTCP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "tcp")
	case layers.LayerTypeUDP:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "udp")
	default:
		netFilePath = filepath.Join(procPath, strconv.Itoa(pid), "net", "raw")
	}

	var file []byte
	file, err = ioutil.ReadFile(netFilePath)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to search inode from net of pid")
		return
	}

	entryScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	entryScanner.Scan() // Skip header line
	retrieveFunction = func() (entry [3]string, exist bool) {
		logrus.Debugln("trying to retrieve entry of socket")

		entryScan:
		exist = entryScanner.Scan()
		if !exist {
			logrus.Debugln("entry not exist")
			return
		}
		columnScanner := bufio.NewScanner(strings.NewReader(entryScanner.Text()))
		columnScanner.Split(bufio.ScanWords)
		argFields.WithField("entry", entryScanner.Text()).Trace("checking the entry")
		checkColumn:
		for columnCounter := 0; columnScanner.Scan(); columnCounter++ {
			switch columnCounter {
			case localAddressColumn:
				entry[0] = columnScanner.Text()
			case remoteAddressColumn:
				entry[1] = columnScanner.Text()
			case inodeColumn:
				entry[2] = columnScanner.Text()
				break checkColumn
			}
		}
		if entry[2] == "0" {
			goto entryScan
		}
		logrus.WithFields(logrus.Fields{
			"local_address": entry[0],
			"rem_address": entry[2],
			"inode": entry[2],
		}).Debug("entry retrieved")
		return
	}
	return
}

// SearchInodeFromNetOfPid returns inode from net of a specific pid in proc filesystem.
func SearchInodeFromNetOfPid(socket *Socket, pid int) (inode uint64, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"target_socket": socket,
		"pid": pid,
	})
	argFields.Debug("trying to search inode from net of pid")

	// Make local_address and rem_address string
	socketLocalPort := fmt.Sprintf("%04X", socket.LocalPort)
	socketRemoteAddr := fmt.Sprintf("%s:%04X", IPtoa(socket.RemoteIP), socket.RemotePort)
	argFields.WithFields(logrus.Fields{
		"socket_local_port_string": socketLocalPort,
		"socket_remote_address_string": socketRemoteAddr,
		}).Trace("the strings for comparison created")

	// Search entry of net socket
	retrieveSocketEntry, err := MakeRetrieveSocketEntryFunction(socket.Protocol, pid)
	if err != nil {
		return
	}
	for entry, exist := retrieveSocketEntry(); exist; entry, exist = retrieveSocketEntry() {
		if !strings.HasSuffix(entry[0], socketLocalPort) {
			argFields.WithField("net_local_port", entry[0]).Trace("the entry skipped")
			continue
		}
		// server process makes 00000000:0000 rem_address entry
		if strings.HasSuffix(entry[1], "0000") || entry[1] == socketRemoteAddr {
			inode, err = strconv.ParseUint(entry[2], 10, 64)
			argFields.WithField("socket_inode", inode).Debug("inode found")
			return
		}
	}
	err = errors.New("inode not found")
	argFields.WithField("error", err).Debug("failed to search inode from net of pid")
	return
}

// RetrieveAllInodeFromRawOfPid return all inodes of specific process id.
func RetrieveAllInodeFromRawOfPid(pid int) (allInode []uint64, err error) {
	argFields := logrus.WithField("process_id", pid)
	argFields.Debug("trying to retrieve all inode from net of pid")

	var retrieveSocketEntry func() ([3]string, bool)
	retrieveSocketEntry, err = MakeRetrieveSocketEntryFunction(layers.LayerTypeICMPv4, pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to retrieve all inode from net of pid")
		return
	}
	for entry, exist := retrieveSocketEntry(); exist; entry, exist = retrieveSocketEntry(){
		var inode uint64
		inode, err = strconv.ParseUint(entry[2], 10, 64)
		allInode = append(allInode, inode)
	}
	argFields.WithField("all_inode", allInode).Debug("all inode retrieved")
	return
}

// SearchProcessOfContainerFromInode return Process struct of the process that have specific socket inode.
func SearchProcessOfContainerFromInode(container *container.Container, inode uint64) (process *Process, err error) {
	argFields := logrus.WithFields(logrus.Fields{
		"communicated_container": container,
		"inode": inode,
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

	inodeStr := strconv.FormatUint(inode, 10)

	// Check inode of pids
	for pids.Len() != 0 {
		pid := pids.Pop()
		argFields.WithField("popped_pid", pid).Trace("pid popped from pid stack")
		if SocketInodeExists(pid, inodeStr) {
			process, err = MakeProcessStruct(pid)
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

// MakeProcessStruct return Process struct of specified pid.
func MakeProcessStruct(pid int) (process *Process, err error) {
	argFields := logrus.WithField("pid", pid)
	argFields.Debug("trying to make process struct")

	var executable, path string
	executable, err = RetrieveProcessName(pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to make process struct")
		return
	}
	argFields.WithField("retrieved_executable", executable).Trace("executable retrieved")
	path, err = RetrieveProcessPath(pid)
	if err != nil {
		argFields.WithField("error", err).Debug("failed to make process struct")
		return
	}
	argFields.WithField("retrieved_path", path).Trace("path retrieved")

	process = &Process{pid, executable, path}
	argFields.WithField("process", process).Debug("the process struct made")
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
func SocketInodeExists(pid int, inodeStr string) bool {
	argFields := logrus.WithFields(logrus.Fields{
		"pid": pid,
		"socket_inode": inodeStr,
	})
	argFields.Debug("trying to check whether the process has socket inode")

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

// SocketInodeExists reports whether the process has namespace process id.
func NSpidExists(pid int, nspidStr string) bool {
	argFields := logrus.WithFields(logrus.Fields{
		"pid": pid,
		"nspid": nspidStr,
	})
	argFields.Debug("trying to check whether the process has namespace process id")

	var file []byte
	file, err := ioutil.ReadFile(filepath.Join(procPath, strconv.Itoa(pid), "status"))
	if err != nil {
		argFields.WithField("error", err).Debug("failed to check whether the process has nspid")
		return false
	}
	rowScanner := bufio.NewScanner(strings.NewReader(*(*string)(unsafe.Pointer(&file))))
	for rowScanner.Scan() {
		rowText := rowScanner.Text()
		if strings.HasPrefix(rowText, "NSpid") {
			if strings.HasSuffix(rowText, nspidStr) {
				return true
			}
			break
		}
	}

	argFields.WithField("error", "nspid not found").Debug("failed to check whether the process has namespace process id")
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
