//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* Backlog congestion levels */
#define NET_RX_SUCCESS		0	/* keep 'em coming, baby */
#define NET_RX_DROP		1	/* packet dropped */

#define STACK_DEPTH 100 
typedef u64 stack[STACK_DEPTH];

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    __type(value, stack);
    __uint(max_entries, 1 << 14);
} stacks SEC(".maps");

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14);
    __type(value, struct event);
} events SEC(".maps");

struct event {
    u32 pid;
    u32 stack_id;
    u8 comm[TASK_COMM_LEN];
};


SEC("tracepoint/netif_receive_skb")
int trigger(struct __sk_buff *ctx){
// SEC("kprobe/sys_execve")
// int kprobe_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 stack_id = bpf_get_stackid(ctx, &stacks, 0);

    if (pid != 20085){
        return NET_RX_SUCCESS;
    }

    struct event *info;
    info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!info) {
        return NET_RX_SUCCESS;
    }

    

    info->pid = pid;
    info->stack_id = stack_id;
    bpf_get_current_comm(&info->comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(info, 0);

    return NET_RX_SUCCESS;
}
