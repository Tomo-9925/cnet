package proc

import "github.com/tomo-9925/cnet/pkg/container"

// Process is information about process needed to analyze communications of container.
type Process struct {
	Executable string
	Path       string
	Pid        int
	Inode      uint64
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
		if err != nil {
			return
		}
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
		for columnCounter := 0; columnScanner.Scan(); columnCounter++ {
			switch columnCounter {
			case 1:
				if !strings.HasSuffix(columnScanner.Text(), socketLocalPort) {
					break
				}
			case 2:
				remoteAddr = columnScanner.Text()
			case 9:
				if strings.HasSuffix(remoteAddr, "0000") {
					inode, err = strconv.ParseUint(columnScanner.Text(), 10, 64)
				} else if remoteAddr == socketRemoteAddr {
					inode, err = strconv.ParseUint(columnScanner.Text(), 10, 64)
					return
				}
				break
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
	containerdShimPid, err = GetPPID(container.Pid)
	if err != nil {
		return
	}
	var childrenPIDs []int
	childrenPIDs, err = GetChildrenPIDs(containerdShimPid)
	if err != nil {
		return
	}
	var pids pidStack
	pids.Push(childrenPIDs...)

	// Check inode of pids
	inodeStr := strconv.FormatUint(inode, 10)
	for pids.Len() != 0 {
		pid := pids.Pop()
		processDirPath := filepath.Join(procPath, strconv.Itoa(pid))
		fdDirPath := filepath.Join(processDirPath, "fd")
		var fdFiles []os.FileInfo
		fdFiles, err = ioutil.ReadDir(fdDirPath)
		if err != nil {
			return
		}
		for _, fdFile := range fdFiles {
			fdFilePath := filepath.Join(fdDirPath, fdFile.Name())
			var linkContent string
			linkContent, err = os.Readlink(fdFilePath)
			if err != nil {
				return
			} else if strings.Contains(linkContent, inodeStr) {
				var commFile []byte
				commFile, err = ioutil.ReadFile(filepath.Join(processDirPath, "comm"))
				if err != nil {
					return
				}
				var processPath string
				processPath, err = os.Readlink(filepath.Join(processDirPath, "exe"))
				if err != nil {
					return
				}
				return &Process{
					Executable: strings.TrimSuffix(*(*string)(unsafe.Pointer(&commFile)), "\n"),
					Path:       processPath,
					Pid:        pid,
					Inode:      inode,
				}, err
			}
		}
		childrenPIDs, err = GetChildrenPIDs(pid)
		if err != nil {
			return
		}
		pids.Push(childrenPIDs...)
	}
	return process, errors.New("process not found")
}

// GetPPID gets the PPID from stat of proc filesystem.
func GetPPID(pid int) (ppid int, err error) {
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

// GetChildrenPIDs gets children PIDs from children of proc filesystem.
func GetChildrenPIDs(pid int) (childrenPIDs []int, err error) {
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
		childrenPIDs = append(childrenPIDs, pid)
	}
	return
}
