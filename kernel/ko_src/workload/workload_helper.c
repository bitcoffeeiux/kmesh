/*
 * Copyright 2024 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */

#include <linux/net.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <net/sock.h>
#include "migration.h"
#include "workload_helper.h"

typedef long (*migration_socket_func)(struct socket* sock, int role);
extern migration_socket_func migration_socket;

typedef long (*sock_owner_by_me_func)(struct sock* sock);
extern sock_owner_by_me_func sock_owner_by_me;

static int get_openfile(struct socket* sock)
{
    struct files_struct *current_files;
    struct fdtable *files;
    struct file *sock_filp;
    int open_fd = -1;
    int i;
    
    sock_filp = sock->file;
    if (!sock_filp) {
        pr_err("socket file is null\n");
        return open_fd;
    }

    rcu_read_lock();
    current_files = current->files;
    files = files_fdtable(current_files);
    for (i = 0; i < files->max_fds; i++) {
        if (sock_filp == files->fd[i]) {
            open_fd = i;
            break;
        }
    }
    rcu_read_unlock();
    return open_fd;
}

static long _migration_socket(struct socket* sock, int role)
{
    info inf = {0};
    int flags = SOCK_STREAM & ~SOCK_TYPE_MASK;
    if (!sock) {
        pr_err("socket is null point!\n");
        return -EPERM;
    }
    if (!sock->sk) {
        pr_err("sk is null point!\n");
        return -EPERM;
    }
    if (sock->sk->ex_task) {
        // migrationing, don need migrate again
        return 0;
    }
    inf.sock_fd = get_openfile(sock);
    if (inf.sock_fd < 0) {
        pr_err("migration failed! can not found valid socket fd, role is %d\n", role);
        return -EPERM;
    }
    inf.role = role;
    sock->sk->ex_task = current;
    sock->sk->current_task = NULL;
    send_sockfd(&inf);
    return 0;
}

int __init workload_helper_ext_init(void)
{
    migration_socket = _migration_socket;
    return 0;
}

void __exit workload_helper_ext_exit(void)
{
    migration_socket = NULL;
}