//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf kprobe_pin.c -- -I../headers

package main

import (
	"log"
	"os"
	"path"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	mapKey    uint32 = 0
	bpfFSPath        = "/sys/fs/bpf"
)

func main() {
	fn := "sys_execve"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	pinPath := path.Join(bpfFSPath, fn)
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			/*
				Pin the map to the BPF filesystem and configure the library to automatically re-write it in the BPF
				Program. so it can be re-use if it already exists or create it if not
			*/
			PinPath: pinPath,
		},
	}); err != nil {
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

	log.Println("Waiting for events..")

	for range ticker.C {
		var value uint64
		if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}

		log.Printf("%s called %d times\n", fn, value)
	}
}
