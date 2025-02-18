//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };

    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };

    short unsigned int skc_family;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct tcp_sock {
    u32 srtt_us; 
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} events SEC(".maps");

struct event {
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u32 srtt;
};

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }

    struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
    if (!ts) {
        return 0;
    }

    struct event *tcp_info; 
    tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if(!tcp_info){
        return 0;
    }

    tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
    tcp_info->daddr = sk->__sk_common.skc_daddr;
    tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
    tcp_info->sport = sk->__sk_common.skc_num;

    tcp_info->srtt = ts->srtt_us >> 3;
    tcp_info->srtt /= 1000;

    bpf_ringbuf_submit(tcp_info, 0);

    return 0;
}