package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf net_stack.c -- -I../headers
func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading ojects: %v", err)
	}

	defer objs.Close()

	tp, err := link.Tracepoint("net", "netif_receive_skb", objs.Trigger, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}

	defer tp.Close()
	// kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }

	// defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting Event..")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received Signal, exiting..")
				return
			}

			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s\n", err)
			continue
		}

		log.Printf("pid: %d\tstackId: %d\tcomm: %s\n", event.Pid, event.StackId, event.Comm)

		ips := make([]uint64, 100)
		if err := objs.Stacks.Lookup(event.StackId, ips); err != nil {
			log.Printf("failed to lookup: %v\n", err)
			continue
		}

		log.Println("[instruction address]")
		for _, ip := range ips {
			if ip == 0 {
				continue
			}
			log.Printf("IP: %x", ip)
		}

	}
}
