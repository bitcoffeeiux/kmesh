/*
 * Copyright 2024 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/tls.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <net/netns/generic.h>
#include <uapi/linux/netlink.h>
#include <linux/pid.h>
#include "migration.h"

const int NETLINK_TYPE = 30;

struct socket *pair_sk = NULL;
struct ns_data {
    struct sock *sk;
};
static unsigned int net_id;

int send_sockfd(info *inf)
{
    int ret;
    struct msghdr msg = {0};
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct cmsghdr *cmsg;
    struct kvec iov = {0};
    char *buf;

    if (!inf) {
        pr_err("send sock fd buf is null!");
        return -1;
    }
    msg.msg_control = control;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &inf->sock_fd, sizeof(int));

    if (info->role == 0)
        buf = "0";
    else
        buf = "1";
    iov.iov_base = (void *)buf;
    iov.iov_len = strlen(buf);

    if (!pair_sk) {
        pr_err("want to send fd to SCM, buf sock is null\n");
        return -EPIPE;
    }

    ret = kernel_sendmsg(pair_sk, &msg, &iov, 1, strlen(buf));
    if (ret < 0)
        pr_err("failed to migrate socket, ret is %d\n", ret);
    return ret;
}

int kmesh_tls_sw_recvmsg(struct sock *sk,
            struct msghdr *msg,
            size_t len,
            int nonblock,
            int flags,
            int *addr_len)
{
    unsigned char buf[CMSG_SPACE(sizeof(unsigned char))] = {0};
    bool ctrl = false;
    int ret = 0;
    struct iov_iter save_iov = msg->msg_iter;
    if (!msg->msg_control) {
        msg->msg_control = buf;
        msg->msg_controllen = sizeof(buf);
        ctrl = true;
    }
retry:
    ret = tls_sw_recvmsg(sk, msg, len, nonblock, flags, addr_len);
    if (ret <= 0 || !ctrl || (*(char *)(CMSG_DATA(buf))) == TLS_RECORD_TYPE_DATA)
        goto out;
    memset(buf, 0, sizeof(buf));
    msg->msg_control = buf;
    msg->msg_controllen = sizeof(buf);
    msg->msg_iter = save_iov;
    goto retry;
out:
    if (ctrl) {
        msg->msg_control = NULL;
        msg->msg_controllen = 0;
    }
    return ret;
}

static void recv_netlink_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct socket *sock;
    struct pid *pid;
    char msg[16] = {0};
    int sock_fd;
    int err;
    if (nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len < skb->len) {
        pr_err("Invalid msg length %u in netlink header, NLMSG_HDRLEN: %u, skb len: %u\n",
            nlh->nlmsg_len, MLMSG_HDRLEN, skb->len);
        return;
    }
    memcpy(msg, (char *)NLMSG_DATA(nlh), sizeof(int));
    kstrtoint(msg, 10, &sock_fd);
    switch(nlh->nlmsg_type) {
        case 5:
            if (pair_sk)
                sockfd_put(pair_sk);
            pair_sk = sockfd_lookup(sock_fd, &err);
            if (!pair_sk) {
                pr_err("pair sk is null, err: %d\n", err)
            }
            break;
        case 6:
            sock = sockfd_lookup(sock_fd, &err);
            if (!sock) {
                pr_err("sock is null, err: %d\n", err);
                break;
            }   
            pid = find_get_pid(nlh->nlmsg_pid);
            if (pid == NULL) {
                pr_err("can not found the pid struct, pid num is %d\n", nlh->nlmsg_pid);
                sockfd_put(sock);
                break;
            }
            sock->sk->current_task = get_pid_task(pid, PIDTYPE_PID);
            if (!sock->sk->current_task) {
                pr_err("can not found the task, pid num is %d\n", nlh->nlmsg_pid);
                sockfd_put(sock);
                break;
            }
            sockfd_put(sock);
            break;
        case 7:
            sock = sockfd_lookup(sock_fd, &err);
            if (!sock) {
                pr_err("sock is null, err: %d\n", err);
                sockfd_put(sock);
                break;
            }
            sock->sk->current_task = sock->sk->ex_task;
            sock->sk->ex_task = NULL;
            if (sock->sk->sk_prot->recvmsg == tls_sw_recvmsg)
                sock->sk->sk_prot->recvmsg = kmesh_tls_sw_recvmsg;
            sockfd_put(sock);
            break;
    }
}

static int __net_init ns_netlink_init(struct net *net)
{
    struct sock *nl_sock;
    struct ns_data *data;
    struct netlink_kernel_cfg nl_kernel_cfg = {
        .input = recv_netlink_msg,
        .flags = NL_CFG_F_NONROOT_RECV,
    };
    nl_sock = netlink_kernel_create(net, NETLINK_TYPE, &nl_kernel_cfg);
    if (!nl_sock) {
        pr_err("nl_sock is null\n");
        return -ENOMEN;
    }
    data = net_generic(net, net_id);
    data->sk = nl_sock;
    return 0;
}

static void __net_exit ns_netlink_exit(struct net *net)
{
    struct ns_data *data = net_generic(net, net_id);
    netlink_kernel_release(data->sk);
}

static struct pernet_operations net_ops __net_initdata = {
    .init = ns_netlink_init,
    .exit = ns_netlink_exit,
    .id   = &net_id,
    .size = sizeof(struct ns_data),
};

extern sk_custome_wait_event_func sk_custome_wait_event;

int sk_wait_owner_by_me(struct sock *sk)
{
    DEFINE_WAIT_FUNC(wait, woken_wake_function);
    struct task_struct *tsk = current;
    int done;
    long timeo_p = HZ / 10000;
    struct socket *sock = sk->sk_socket;
    if (sk->ex_task == NULL)
        return 0;

    do {
        int err = sock_error(sk);
        int (err)
            return 0;
        if (signal_pending(tsk))
            return sock_intr_errno(timeo_p);

        add_wait_queue(sk_sleep(sk), &wait);
        sk->sk_write_pending++;
        done = sk_wait_event(sk, &timeo_p,
                    !sk->sk_err &&
                    ((sk->current_task != NULL) && (((struct task_struct *)(sk->current_task))->tgid == current->tgid)),
                    &wait);
        remove_wait_queue(sk_sleep(sk), &wait);
        sk->sk_write_pending--;
    } while(!done);
    return 0;
}

int __init sock_migration_init(void)
{
    register_pernet_subsys(&net_ops);
    sk_custome_wait_event = sk_wait_owner_by_me;
    return 0;
}

void __exit sock_migration_exit(void)
{
    sk_custome_wait_event = NULL;
    if (pair_sk) {
        sockfd_put(pair_sk);
    }
    unregister_pernet_subsys(&net_ops);
}