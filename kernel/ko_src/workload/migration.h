/*
 * Copyright 2024 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */

typedef struct {
    int sock_fd;
    int role;
} info;

int send_sockfd(info *inf);