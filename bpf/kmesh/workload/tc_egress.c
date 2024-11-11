// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "tc.h"
#include "bpf_log.h"
#include "ipsec_map.h"

struct nodeinfo * getNodeInfo(struct tc_info *info)
{
    struct lpm_key key = {0};
    struct bpf_sock_tuple tuple_key = {0};
    if (is_ipv4(info)) {
        key.trie_key.prefixlen = 32;
        key.ip.ip4 = info->iph->daddr;
    } else if (is_ipv6(info)){
        key.trie_key.prefixlen = 128;
        IP6_COPY(key.ip.ip6, info->ip6h->daddr.s6_addr32);
    } else {
        return NULL;
    }
    return bpf_map_lookup_elem(&map_of_nodeinfo, &key);
}

SEC("tc_egress")
int tc_mark_encrypt(struct __sk_buff *ctx)
{
    struct nodeinfo *nodeinfo;

    struct tc_info info = {0};

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }

    nodeinfo = getNodeInfo(&info);
    if (!nodeinfo) {
        return TC_ACT_OK;
    }
    ctx->mark = ((nodeinfo->nodeid) << 12) + ((nodeinfo->spi) << 3) + 0xe00;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;