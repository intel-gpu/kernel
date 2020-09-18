/* SPDX-License-Identifier: MIT */

/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef DEBUGFS_GT_IRQ_H
#define DEBUGFS_GT_IRQ_H

struct intel_gt;
struct dentry;

void debugfs_gt_register_irq(struct intel_gt *gt, struct dentry *root);

#endif /* DEBUGFS_GT_IRQ_H */
