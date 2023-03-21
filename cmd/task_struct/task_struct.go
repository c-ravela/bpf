package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//Ebpf map item structure
type event_data struct {
	Comm            [16]uint8
	Exec_id         uint64
	Pid             uint32
	Tgid            uint32
	On_rq           int32
	On_cpu          int32
	State           uint32
	Wake_cpu        int32
	Recent_used_cpu int32
	Prio            int32
	Normal_prio     int32
	Static_prio     int32
	Rt_priority     uint32
	Policy          uint32
	Nr_cpus_allowed int32
	Exit_state      int32
	Exit_code       int32
	Exit_signal     int32
	Pdeath_signal   int32
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS bpf index.bpf.c -- -I../../headers

func main() {
	err := rlimit.RemoveMemlock()
	must("Error Removing the memlock", err)

	bpfObj := bpfObjects{}
	err = loadBpfObjects(&bpfObj, nil)
	must("Error Loading the ebpf objects", err)

	hook, err := link.Tracepoint("syscalls", "sys_enter_execve", bpfObj.Task, nil)
	must("Error While Attaching the program", err)
	defer hook.Close()

	//Create perf map reader
	perfReader, err := perf.NewReader(bpfObj.Event, 4096)
	must("Error while creating map reader", err)
	defer perfReader.Close()

	//reads data from map
	mapDataEmitter := make(chan perf.Record)
	go func() {
		defer close(mapDataEmitter)

		for {
			record, err := perfReader.Read()
			must("Error while reading map", err)

			mapDataEmitter <- record
		}

	}()

	//parses map data and prints to screen
	prompt("Waiting for event to trigger!")
	for {
		record := <-mapDataEmitter

		var row event_data
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &row)
		must("Error while parsing the data", err)

		printToScreen(row)
		prompt("Waiting for event to trigger!")
	}
}

func must(msg string, err error) {
	if err != nil {
		fmt.Println("%s : %v", msg, err)
	}
}

func printToScreen(row event_data) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Command: %s\n", row.Comm)
	fmt.Printf("Parent Exec ID: %d\n", row.Exec_id)
	fmt.Printf("Process ID: %d\n", row.Pid)
	fmt.Printf("Thread ID: %d\n", row.Tgid)
	fmt.Printf("On Rq: %d\n", row.On_rq)
	fmt.Printf("On Cpu: %d\n", row.On_cpu)
	fmt.Printf("State : %d\n", row.State)
	fmt.Printf("Wake Cpu : %d\n", row.Wake_cpu)
	fmt.Printf("Recently used Cpu : %d\n", row.Recent_used_cpu)
	fmt.Printf("Priority : %d\n", row.Prio)
	fmt.Printf("Normal Priority : %d\n", row.Normal_prio)
	fmt.Printf("Static Priority : %d\n", row.Static_prio)
	fmt.Printf("Rt Priority : %d\n", row.Rt_priority)
	fmt.Printf("Policy : %d\n", row.Policy)
	fmt.Printf("No of CPU's allowed : %d\n", row.Nr_cpus_allowed)
	fmt.Printf("Exit State : %d\n", row.Exit_state)
	fmt.Printf("Exit Code : %d\n", row.Exit_code)
	fmt.Printf("Exit Signal : %d\n", row.Exit_signal)
	fmt.Printf("Pdeath Signal : %d\n", row.Pdeath_signal)
	fmt.Println("-----------------------------------------")
}

func prompt(msg string) {
	fmt.Printf("\n %s \r", msg)
}
