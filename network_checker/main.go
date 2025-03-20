package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	RTT     = 1
	RTO     = 2
	RETRANS = 3
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event bpf checker.c -- -I../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, unix.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	cgroupPath, err := findCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.bpfPrograms.OnBpfSockops,
		Attach:  ebpf.AttachCGroupSockOps,
	})

	if err != nil {
		log.Fatal(err)
	}

	defer link.Close()

	log.Printf("eBPF program loaded and attached on cgroup %s\n", cgroupPath)

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	defer rd.Close()

	go readLoop(rd)
	<-stopper
}

func readLoop(rd *ringbuf.Reader) {
	var event bpfEvent
	log.Println("sip sport dip dport srtt")
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}

			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		switch event.Type {
		case RTT:
			if event.Srtt <= 0 {
				continue
			}
			log.Printf("%-15s %-6d -> %-15s %-6d %-6d",
				intToIP(event.Saddr),
				event.Sport,
				intToIP(event.Daddr),
				event.Dport,
				event.Srtt,
			)
		case RTO:
			log.Println("TRIGGER RTO")
			break

		case RETRANS:
			log.Println("TRIGGER RETRANS")
			break

		}

	}
}

func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	var st unix.Statfs_t
	err := unix.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}

	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}

	return cgroupPath, nil
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
