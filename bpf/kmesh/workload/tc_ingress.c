// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "tc.h"
#include "bpf_log.h"
#include "common.h"
#include "ipsec_map.h"

static inline bool is_ipsec_pkt(struct tc_info *info)
{
    struct iphdr *ipv4;
    struct ipv6hdr *ipv6;
    if (is_ipv4(info)) {
        ipv4 = info->iph;
        return ipv4->protocol == IPPROTO_ESP;
    } else if (is_ipv6(info)) {
        ipv6 = (struct ipv6hdr *)info->iph;
        return ipv6->nexthdr == IPPROTO_ESP;
    }
    return false;
}

SEC("tc_ingress")
int tc_mark_decrypt(struct __sk_buff *ctx)
{
    __u16 nodeid;
    struct nodeinfo *nodeinfo;
    struct tc_info info = {0};

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }

    if (!is_ipsec_pkt(&info)) {
        return TC_ACT_OK;
    }
    nodeinfo = getNodeInfo(ctx, &info, info.iph->saddr, info.ip6h->saddr.s6_addr32);
    if (!nodeinfo) {
        return TC_ACT_OK;
    }
    nodeid = nodeinfo->nodeid;
    ctx->mark = (nodeid << 12) + 0xd00;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;