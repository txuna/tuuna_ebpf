package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Ksym struct {
	Addr    string
	SymName string
	ModName string
}

type Handler struct {
	Ksyms []*Ksym
	Path  string
}

func (h *Handler) Refresh() {
	file, err := os.Open(h.Path)
	if err != nil {
		log.Fatalln("Error opening file:", err)
	}
	defer file.Close()

	modName := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// 공백(Space) 기준으로 Split
		parts := strings.Fields(line)

		// 최소한 "주소, 타입, 심볼 이름"이 존재해야 함
		if len(parts) < 3 {
			continue
		}

		switch parts[1] {
		case "b", "B", "d", "D", "r", "R":
			continue
		}

		if len(parts) == 4 {
			modName = parts[3]
			continue
		}

		h.Ksyms = append(h.Ksyms, &Ksym{
			Addr:    parts[0],
			SymName: parts[2],
			ModName: modName,
		})
	}

}

func (h *Handler) Find(addr uint64) *Ksym {
	for _, sym := range slices.Backward(h.Ksyms) {
		n, err := strconv.ParseUint(sym.Addr, 16, 64)
		if err != nil {
			fmt.Println("Error2: ", err)
			return nil
		}
		if addr >= n {
			return sym
		}

		continue
	}

	return nil
}

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

	h := &Handler{
		Ksyms: make([]*Ksym, 0),
		Path:  "/proc/kallsyms",
	}

	h.Refresh()

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
			sym := h.Find(ip)
			if sym == nil {
				continue
			}
			log.Printf("IP: %x - %s\n", ip, sym.SymName)
		}

	}
}
