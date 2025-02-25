package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf tcx.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specifiy a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
	})

	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}

	defer l.Close()

	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)

	l2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})

	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}

	defer l2.Close()

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatCounters(objs.IngressPktCount, objs.EgressPktCount)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}

		log.Printf("Packet Count: %s\n", s)
	}
}

func formatCounters(ingressVar, egressVar *ebpf.Variable) (string, error) {
	var (
		ingressPacketCount uint64
		egressPacketCount  uint64
	)

	if err := ingressVar.Get(&ingressPacketCount); err != nil {
		return "", err
	}

	if err := egressVar.Get(&egressPacketCount); err != nil {
		return "", err
	}

	return fmt.Sprintf("%10v Ingress, %10v Egress", ingressPacketCount, egressPacketCount), nil
}
