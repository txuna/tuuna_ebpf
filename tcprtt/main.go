//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event bpf tcprtt.c -- -I../headers

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, unix.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpClose,
	})

	if err != nil {
		log.Fatal(err)
	}

	defer link.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	defer rd.Close()

	log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"RTT",
	)

	go readLoop(rd)

	<-stopper
}

func readLoop(rd *ringbuf.Reader) {
	var event bpfEvent
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

		log.Printf("%-15s %-6d -> %-15s %-6d %-6d",
			intToIP(event.Saddr),
			event.Sport,
			intToIP(event.Daddr),
			event.Dport,
			event.Srtt,
		)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, ipNum)
	return ip
}
