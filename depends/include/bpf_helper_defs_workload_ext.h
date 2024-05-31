/*
 * Copyright 2023 The Kmesh Authors.
 */

/*
 * Note: when compiling kmesh, the helper function IDs listed in this
 * file will be updated based on the file "/usr/include/linux/bpf.h"
 * in the compilation environment. In addition, newly developed helper
 * functions will also be added here in the future.
 *
 * By default, these IDs are in the 5.10 kernel with kmesh kernel patches.
 */

/*based on openEuler22.03LTS-SP1*/
static void *(*bpf_migration_socket)(void *ctx) = (void *)170;
static void *(*bpf_sock_own_by_me)(void *ctx) = (void *)171;

const int BPF_SOCK_OPS_TCP_RECVMSG_CB = 16;
const int SK_RETRY = 2;