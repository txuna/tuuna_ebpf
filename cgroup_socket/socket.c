//go:build ignore


#include "common.h"
#include "bpf_sock.h"
#include "bpf_helpers.h"

// #include <bpf/bpf.h>
u64 invocations = 0, in_use = 0;
// struct {
//     __uint(type, BPF_MAP_TYPE_SK_STORAGE);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
//     __type(key, int);
//     __type(value, int);
// } sk_map SEC(".maps");

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") sk_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(int),
	.max_entries = 1024,
};

SEC("cgroup/sock_create")
int awake_sock_create(struct bpf_sock *ctx) {
    if(ctx->type != 2){
        return 1;
    } 

    // u32 port = ctx->src_port;
    // bpf_printk("bind port: %d", port);   
    /*
        Get a bpf-local-storage from a sk
        논리적으로는 sk를 키로 하는 맵에서 값을 가져오는 것으로 생각할 수 있다.
        키가 전체 소켓
        맵도 BPF_MAP_TYPE_SK_STORAGE인점을 제외하면 bpf_map_lookup_elem(map, &sk)와 다를게 없음
    */
    // sk_storage = bpf_sk_storage_get(&sk_map, ctx, 0, BPF_SK_STORAGE_GET_F_CREATE);
    // if(!sk_storage) {
    //     return 0;
    // }

    // *sk_storage = 0xdeadbeef;

    __sync_fetch_and_add(&invocations, 1);
    if(in_use > 0) {
        /*
            BPF_CGROUP_INET_SOCK_RELEASE is _not_ called
            when we return an error from the BPF
            program!
        */

       return 0;
    }

    __sync_fetch_and_add(&in_use, 1);
    return 1;
}