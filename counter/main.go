package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock: ", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel
	/*
		counterObjects는 맵 및 프로그램 객체에 대한 nil 포인터를 포함하는 구조체이다.
		loadCounterObjects를 호출하면 필드에 선언된 구조체 태그를 기반으로 필드가 채워진다.
		이 메커니즘은 Map & Program 객체에 대한 컬렉션을 문자열로 검사할 때 발생할 수 있는 많은 반복을 줄여줌

		추가적으로 counterObjects는 컴파일 타임 조회로 전환하여 유형 안정성을 추가한다.
		Map & Program이 ELF에 나타나지 않으면 구조체 필드로 표시되자 않고 Go 어플리케이션이 컴파일 되지 않으므로 런타임 오류의 전체 클래스가 제거
	*/
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}

	//https://ebpf-go.dev/concepts/object-lifecycle/
	defer objs.Close()

	ifname := "eth0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s:%s", ifname, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatal("Attaching XDP: ", err)
	}

	/*
		프로그램 - 인터페이스 연결의 파일 디스크립터를 닫음
		Link.Pined가 bpf 파일 시스템에 연결되어 있지 않은 경우 들어오는 패킷에서 프로그램이 실행되지 않는다.
	*/
	defer link.Close()

	log.Printf("Counting incoming packets on %s..\n", ifname)

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup: ", err)
			}

			log.Printf("Received %d packets", count)

		case <-stop:
			log.Println("Receive signal, exiting...")
			return
		}
	}
}
