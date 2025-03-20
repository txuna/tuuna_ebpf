//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_sockops.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define SOCKOPS_MAP_SIZE 65535
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

enum {
    SOCK_TYPE_ACTIVE = 0,
    SOCK_TYPE_PASSIVE = 1,
};

#define RTT 1
#define RTO 2
#define RETRANS 3

struct event {
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u32 srtt;
    u32 type; /* rtt 전송인지, rto, retrans 구별자*/
};


// 링버퍼 전송용
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
}events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SOCKOPS_MAP_SIZE);
    __type(key, struct sk_key);
    __type(value, struct sk_info);
} map_estab_sk SEC(".maps");

struct sk_key {
    u32 local_ip4;
    u32 remote_ip4;
    u32 local_port;
    u32 remote_port;
};

struct sk_info {
    struct sk_key sk_key;
    u8 sk_type;
};

/*
bpf_get_current_pid_tgid
https://github.com/cilium/ebpf/discussions/1373
https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
*/

static inline int init_sk_key(struct bpf_sock_ops *skops, struct sk_key *sk_key) {
    sk_key->local_ip4 = bpf_ntohl(skops->local_ip4);
    sk_key->remote_ip4 = bpf_ntohl(skops->remote_ip4);
    sk_key->local_port = skops->local_port;
    sk_key->remote_port = bpf_ntohl(skops->remote_port);

    if (sk_key->local_ip4 == 2130706433 ){
        return 0;
    }

    if (sk_key->remote_ip4 == 2130706433 ){
        return 0;
    }

    return 1;
}

static inline void bpf_sock_ops_establish_cb(struct bpf_sock_ops *skops, u8 sock_type) {
    int err; 
    struct sk_info sk_info = {};
    // Only process IPv4 sockets

    if (skops == NULL || skops->family != AF_INET) {
        return;
    }

    // Initialize the 4-tuple key
    if (init_sk_key(skops, &sk_info.sk_key) == 0){
        return;
    }

    sk_info.sk_type = sock_type;

    // Store the socket info in map using the 4-tuple key
    // We keep track of TCP connections in 'established' state

    err = bpf_map_update_elem(&map_estab_sk, &sk_info.sk_key, &sk_info, BPF_NOEXIST);
    if (err != 0) {
        return;
    }

    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG | BPF_SOCK_OPS_RETRANS_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG);
}

static inline void trigger_rto(struct bpf_sock_ops *skops) {
    struct sk_key sk_key = {};
    struct sk_info *sk_info;
    struct event *info;

    init_sk_key(skops, &sk_key);
    sk_info = bpf_map_lookup_elem(&map_estab_sk, &sk_key);
    if (!sk_info) {
        return;
    }

    info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!info) {
        return;
    }

    switch (sk_info->sk_type) {
        case SOCK_TYPE_ACTIVE:
            // If socket is 'active', 'local' means 'source' 
            // and 'remote' means 'destination' 
            info->saddr = sk_info->sk_key.local_ip4;
            info->daddr = sk_info->sk_key.remote_ip4;
            info->sport = sk_info->sk_key.local_port;
            info->dport = sk_info->sk_key.remote_port;
            break;

        case SOCK_TYPE_PASSIVE:
            // If socket is 'passive', 'local' means 'destination'
            // and 'remote' means 'source' 
            info->saddr = sk_info->sk_key.remote_ip4;
            info->daddr = sk_info->sk_key.local_ip4;
            info->sport = sk_info->sk_key.remote_port;
            info->dport = sk_info->sk_key.local_port; 
            break;
    }

    info->type = RTO;
    bpf_ringbuf_submit(info, 0);
}

static inline void trigger_retrans(struct bpf_sock_ops *skops) {
    struct sk_key sk_key = {};
    struct sk_info *sk_info;
    struct event *info;

    init_sk_key(skops, &sk_key);
    sk_info = bpf_map_lookup_elem(&map_estab_sk, &sk_key);
    if (!sk_info) {
        return;
    }

    info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!info) {
        return;
    }

    switch (sk_info->sk_type) {
        case SOCK_TYPE_ACTIVE:
            // If socket is 'active', 'local' means 'source' 
            // and 'remote' means 'destination' 
            info->saddr = sk_info->sk_key.local_ip4;
            info->daddr = sk_info->sk_key.remote_ip4;
            info->sport = sk_info->sk_key.local_port;
            info->dport = sk_info->sk_key.remote_port;
            break;

        case SOCK_TYPE_PASSIVE:
            // If socket is 'passive', 'local' means 'destination'
            // and 'remote' means 'source' 
            info->saddr = sk_info->sk_key.remote_ip4;
            info->daddr = sk_info->sk_key.local_ip4;
            info->sport = sk_info->sk_key.remote_port;
            info->dport = sk_info->sk_key.local_port; 
            break;
    }

    info->type = RETRANS;
    bpf_ringbuf_submit(info, 0);
}

static inline void bpf_sock_ops_rtt_cb(struct bpf_sock_ops *skops) {
    struct sk_key sk_key = {};
    struct sk_info *sk_info;
    struct event *info;

    init_sk_key(skops, &sk_key);
    sk_info = bpf_map_lookup_elem(&map_estab_sk, &sk_key);
    if (!sk_info) {
        return;
    }

    info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!info) {
        return;
    }

    switch (sk_info->sk_type) {
        case SOCK_TYPE_ACTIVE:
            // If socket is 'active', 'local' means 'source' 
            // and 'remote' means 'destination' 
            info->saddr = sk_info->sk_key.local_ip4;
            info->daddr = sk_info->sk_key.remote_ip4;
            info->sport = sk_info->sk_key.local_port;
            info->dport = sk_info->sk_key.remote_port;
            break;

        case SOCK_TYPE_PASSIVE:
            // If socket is 'passive', 'local' means 'destination'
            // and 'remote' means 'source' 
            info->saddr = sk_info->sk_key.remote_ip4;
            info->daddr = sk_info->sk_key.local_ip4;
            info->sport = sk_info->sk_key.remote_port;
            info->dport = sk_info->sk_key.local_port; 
            break;
    }

    info->type = RTT;
    // Extract smoothed RTT
    info->srtt = skops->srtt_us >> 3;
    info->srtt /= 1000;

    bpf_ringbuf_submit(info, 0);
}

static inline void bpf_sock_ops_state_cb(struct bpf_sock_ops *skops) {
    struct sk_key sk_key = {};

    // 이전 상태가 성립상태였다면 삭제
    if (skops->args[0] == TCP_ESTABLISHED) {
        init_sk_key(skops, &sk_key);
        bpf_map_delete_elem(&map_estab_sk, &sk_key);
    }
}

SEC("sockops")
int on_bpf_sockops(struct bpf_sock_ops *skops) {
    u32 op;
    op = skops->op;

    switch (op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            bpf_sock_ops_establish_cb(skops, SOCK_TYPE_ACTIVE);
            break;

        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            bpf_sock_ops_establish_cb(skops, SOCK_TYPE_PASSIVE);
            break;

        // 재전송 시간 아웃 알림
        case BPF_SOCK_OPS_RTO_CB:
            trigger_rto(skops);
            break;

        // 패킷 재전송 알림
        case BPF_SOCK_OPS_RETRANS_CB:
            trigger_retrans(skops);
            break;

        // 모든 왕복에 대한 RTT 호출
        case BPF_SOCK_OPS_RTT_CB:
            bpf_sock_ops_rtt_cb(skops);
            break;

        // 소켓의 상태가 바꼈을 떄 호출됨 argv[0] 이전상태, argv[1] 현재 상태
        case BPF_SOCK_OPS_STATE_CB:
            bpf_sock_ops_state_cb(skops);
            break;

        // syn 패킷을 보냈을 떄
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
            break;
    }
           
    return 0;
}