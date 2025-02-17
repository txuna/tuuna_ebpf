//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf kprobe_percpu.c -- -I../headers

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const mapKey uint32 = 0

func main() {
	fn := "sys_execve"

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}

	defer kp.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("waiting for events..")

	for range ticker.C {
		var all_cpu_value []uint64
		if err := objs.KprobeMap.Lookup(mapKey, &all_cpu_value); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		for cpuid, cpuvalue := range all_cpu_value {
			log.Printf("%s called %d times on CPU%v\n", fn, cpuvalue, cpuid)
		}

		log.Printf("\n")
	}
}
