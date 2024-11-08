// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#include "bpf_log.h"
#include "common.h"
#include "ipsec_map.h"

struct tc_info {
    struct ethhdr *ethh;
    union {
        struct iphdr *iph;
        struct ipv6hdr *ip6h;
    };
};

#define PARSER_FAILED 1
#define PARSER_SUCC   0

static inline bool is_ipv4(struct tc_info *info)
{
    return info->ethh->h_proto == bpf_htons(ETH_P_IP);
}

static inline bool is_ipv6(struct tc_info *info)
{
    return info->ethh->h_proto == bpf_htons(ETH_P_IPV6);
}

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

static inline int parser_tc_info(struct __sk_buff *ctx, struct tc_info *info)
{
    void *begin = (void *)(long)(ctx->data);
    void *end = (void *)(long)(ctx->data_end);

    // eth header
    info->ethh = (struct ethhdr *)begin;
    if ((void *)(info->ethh + 1) > end)
        return PARSER_FAILED;

    // ip4|ip6 header
    begin = info->ethh + 1;
    if ((begin + 1) > end)
        return PARSER_FAILED;
    if (is_ipv4(info)) {
        info->iph = (struct iphdr *)begin;
        if ((void *)(info->iph + 1) > end)
            return PARSER_FAILED;
    } else if (is_ipv6(info)) {
        info->ip6h = (struct ipv6hdr *)begin;
        if ((void *)(info->ip6h + 1) > end)
            return PARSER_FAILED;
    } else
        return PARSER_FAILED;

    return PARSER_SUCC;
}

SEC("tc_ingress")
int tc_mark_decrypt(struct __sk_buff *ctx)
{
    __u32 ipv4;
    __u32 ipv6[4];
    __u16 nodeid;
    struct tc_info info = {0};

    if (parser_tc_info(ctx, &info)) {
        return TC_ACT_OK;
    }

    if (!is_ipsec_pkt(&info)) {
        return TC_ACT_OK;
    }
    if (is_ipv4(&info)) {
        ipv4 = info.iph->saddr;
        nodeid = getNodeIDIPv4(ipv4);
    } else if (is_ipv6(&info)) {
        IP6_COPY(ipv6, info.ip6h->saddr.s6_addr32);
        nodeid = getNodeIDIPv6(ipv6);
    } else {
        return TC_ACT_OK;
    }
    ctx->mark = (nodeid << 12) + 0xd00;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
int _version SEC("version") = 1;