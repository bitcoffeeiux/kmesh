// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "ipsec_map.h"

SEC("tc_egress")
int tc_mark_encrypt(struct __sk_buff *ctx)
{
    struct nodeinfo *nodeinfo;

    nodeinfo = bpf_sk_storage_get(&map_of_sk_storage, ctx->sk, 0, 0);
    if (nodeinfo) {
        ctx->mark = ((nodeinfo->nodeid) << 12) + ((nodeinfo->spi) << 3) + 0xe00;
    }
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;