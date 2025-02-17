package main

import (
	"log"
	"os"

	"github.com/cilium/ebpf"
)

func main() {
	mapPath := "/sys/fs/bpf/sys_execve/kprobe_map"

	// eBPF 맵을 열어서 가져오기
	bpfMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		log.Fatalf("Failed to load pinned map: %v", err)
	}
	defer bpfMap.Close()

	// 맵 삭제 시도
	err = os.Remove(mapPath)
	if err != nil {
		log.Fatalf("Failed to remove pinned map: %v", err)
	}

	log.Println("Successfully removed pinned map:", mapPath)
}
