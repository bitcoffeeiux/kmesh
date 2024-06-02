/*
 * Copyright 2024 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 */

#include <linux/init.h>
#include <linux/module.h>
#include "migration.h"
#include "workload_helper.h"

static int __init kmesh_workload_init(void)
{
    workload_helper_ext_init();
    return 0;
}

static void __exit kmesh_workload_exit(void)
{
    workload_helper_ext_exit();
}

module_init(kmesh_workload_init);
module_exit(kmesh_workload_exit);

MODULE_LICENSE("GPL");
