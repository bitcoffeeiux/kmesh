// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
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