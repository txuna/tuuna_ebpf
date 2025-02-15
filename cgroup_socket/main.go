//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf socket.c -- -I../headers

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()

	// Get the first-mounted cgroupv2 path
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.AwakeSockCreate,
	})

	if err != nil {
		log.Fatal(err)
	}

	defer link.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var value uint64
		if err := objs.Invocations.Get(&value); err != nil {
			log.Fatal(err)
		}

		if value >= 1 {
			fmt.Println("Invoked!")
		} else {
			fmt.Println("Nothing...")
		}
	}
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
