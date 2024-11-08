// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>
#include "bpf_log.h"
#include "common.h"
#include "ipsec_map.h"

static inline __u16 getNodeIDIPv4(__u32 ipv4)
{
    struct nodeinfo *nodeinfo;
    struct lpm_key key = {0};
    key.trie_key.prefixlen = 32;
    key.ip.ip4 = ipv4;

    nodeinfo = bpf_map_lookup_elem(&map_of_nodeinfo, &key);
    if (!nodeinfo) {
        return 0;
    }
    return nodeinfo->nodeid;
}

static inline __u16 getNodeIDIPv6(__u32 *ipv6)
{
    struct nodeinfo *nodeinfo;
    struct lpm_key key = {0};
    key.trie_key.prefixlen = 128;
    IP6_COPY(key.ip.ip6, ipv6);

    nodeinfo = bpf_map_lookup_elem(&map_of_nodeinfo, &key);
    if (!nodeinfo) {
        return 0;
    }
    return nodeinfo->nodeid;
}

static inline bool is_ipsec_pkt(struct __sk_buff *ctx) {
    return ctx->protocol == IPPROTO_ESP;
}

SEC("tc_ingress")
int tc_mark_decrypt(struct __sk_buff *ctx)
{
    __u32 ipv4;
    __u32 ipv6[4];
    __u16 nodeid;

    if (!is_ipsec_pkt(ctx)) {
        return 0;
    }
    if (ctx->family == AF_INET) {
        ipv4 = ctx->remote_ip4;
        nodeid = getNodeIDIPv4(ipv4);
    } else if (ctx->family == AF_INET6) {
        IP6_COPY(ipv6, ctx->remote_ip6);
        nodeid = getNodeIDIPv6(ipv6);
    } else {
        return 0;
    }
    ctx->mark = (nodeid << 12) + 0xd00;
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;