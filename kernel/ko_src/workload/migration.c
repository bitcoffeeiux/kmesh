/*
 * Copyright 2024 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */

#include "migration.h"

typedef long (*migration_socket_func)(struct socket* sock);
extern migration_socket_func migration_socket;

typedef long (*sock_owner_by_me_func)(struct sock* sock);
extern sock_owner_by_me_func sock_owner_by_me;

static long _migration_socket(struct socket* sock)
{
    int fd;
    int flags = SOCK_STREAM & ~SOCK_TYPE_MASK;
    if (!sock) {
        pr_err("sock is null point!\n");
        return -EPERM;
    }
    if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
        flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;
    flags &= (O_CLOEXEC | O_NONBLOCK);
    fd = get_unused_fd_flags(flags);
    fd_install(fd, sock->file);
    sock->sk->ex_task = current;
    sock->sk->current_task = NULL;
    // todo transfer(fd);
}

static long _sock_owner_by_me(struct sock* sock)
{
    return (sock->current == current);
}

int __init migration_sock_init(void)
{
    migration_socket = _migration_socket;
    sock_owner_by_me = _sock_owner_by_me;
}

void __exit migration_socket_exit(void)
{
    migration_socket = NULL;
    sock_owner_by_me = NULL;
}