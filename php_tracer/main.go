package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event bpf checker.c -- -I../headers

func main() {

}
