/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef __GEN8_PPGTT_H__
#define __GEN8_PPGTT_H__

struct i915_address_space;
struct intel_gt;

void gen8_restore_ppgtt_mappings(struct i915_address_space *vm);
struct i915_ppgtt *gen8_ppgtt_create(struct intel_gt *gt);

#endif
