/*
 * Copyright 2024 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */

#include <linux/net.h>
#include <linux/file.h>
#include <net/sock.h>
#include "migration.h"
#include "workload_helper.h"

typedef long (*migration_socket_func)(struct socket* sock, int role);
extern migration_socket_func migration_socket;

typedef long (*sock_owner_by_me_func)(struct sock* sock);
extern sock_owner_by_me_func sock_owner_by_me;

static long _migration_socket(struct socket* sock, int role)
{
    info inf = {0};
    int flags = SOCK_STREAM & ~SOCK_TYPE_MASK;
    if (!sock) {
        pr_err("sock is null point!\n");
        return -EPERM;
    }
    if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
        flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;
    flags &= (O_CLOEXEC | O_NONBLOCK);
    inf.sock_fd = get_unused_fd_flags(flags);
    fd_install(inf.sock_fd, sock->file);
    inf.role = role;
    sock->sk->ex_task = current;
    sock->sk->current_task = NULL;
    send_sockfd(&inf);
    return 0;
}

static long _sock_owner_by_me(struct sock* sock)
{
    return (sock->current_task == current);
}

int __init workload_helper_ext_init(void)
{
    migration_socket = _migration_socket;
    sock_owner_by_me = _sock_owner_by_me;
    return 0;
}

void __exit workload_helper_ext_exit(void)
{
    migration_socket = NULL;
    sock_owner_by_me = NULL;
}