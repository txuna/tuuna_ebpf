package main

import (
	"errors"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

var progSpec = &ebpf.ProgramSpec{
	Name:    "my_trace_prog",
	Type:    ebpf.TracePoint,
	License: "GPL",
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, unix.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "my_perf_array",
	})

	if err != nil {
		log.Fatalf("creating perf event array: %s", err)
	}

	defer events.Close()

	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}

	defer rd.Close()

	go func() {
		<-stopper
		rd.Close()
	}()

	/*
		Minimal program that writes the static value '123' to the perf ring on
		each event. Note that this program refers to the file descriptor of
		the perf event array ceated above, which needs to be created prior to the program
		being verified by and inserted into the kernel
	*/
	progSpec.Instructions = asm.Instructions{
		// store the integer 123 at FP[-8]
		asm.Mov.Imm(asm.R2, 123),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.Word),

		// load registers with arguments for call of FnPerfEvent
		asm.LoadMapPtr(asm.R2, events.FD()),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -8),
		asm.Mov.Imm(asm.R5, 4),

		// call FnPerfEventOutput, an eBPF kernel helper
		asm.FnPerfEventOutput.Call(),

		// set exit code to 0
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// Instantiate and inser the program into the kernel.
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}

	defer prog.Close()

	/*
		Open a trace event based on a pre-existing kernel hook (tracepoint).
		Each time a userspace program uses the 'openat() syscall, The eBPF
		program specific above will be executed and a '123' value will appear in the perf ring.
	*/

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}

	defer tp.Close()

	log.Println("Waiting for events..")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}

			log.Printf("reading from reader: %s\n", err)
			continue
		}

		log.Println("Record: ", record)
	}
}
