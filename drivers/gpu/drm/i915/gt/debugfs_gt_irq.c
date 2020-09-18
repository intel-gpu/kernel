// SPDX-License-Identifier: MIT

/*
 * Copyright © 2020 Intel Corporation
 */

#include "debugfs_gt.h"
#include "debugfs_gt_irq.h"
#include "i915_drv.h"

static int interrupt_info_show(struct seq_file *m, void *data)
{
	struct intel_gt *gt = m->private;
	struct drm_i915_private *i915 = gt->i915;
	struct intel_uncore *uncore = gt->uncore;
	struct intel_engine_cs *engine;
	enum intel_engine_id id;
	intel_wakeref_t wakeref;
	int i;

	wakeref = intel_runtime_pm_get(uncore->rpm);

	if (IS_CHERRYVIEW(i915)) {
		seq_printf(m, "Master Interrupt Control:\t%08x\n",
			   intel_uncore_read(uncore, GEN8_MASTER_IRQ));

		for (i = 0; i < 4; i++) {
			seq_printf(m, "GT Interrupt IMR %d:\t%08x\n",
				   i, intel_uncore_read(uncore,
							GEN8_GT_IMR(i)));
			seq_printf(m, "GT Interrupt IIR %d:\t%08x\n",
				   i, intel_uncore_read(uncore,
							GEN8_GT_IIR(i)));
			seq_printf(m, "GT Interrupt IER %d:\t%08x\n",
				   i, intel_uncore_read(uncore,
							GEN8_GT_IER(i)));
		}

	} else if (INTEL_GEN(i915) >= 11) {
		seq_printf(m, "Master Interrupt Control:  %08x\n",
			   intel_uncore_read(uncore, GEN11_GFX_MSTR_IRQ));

		seq_printf(m, "Render/Copy Intr Enable:   %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_RENDER_COPY_INTR_ENABLE));
		seq_printf(m, "VCS/VECS Intr Enable:      %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_VCS_VECS_INTR_ENABLE));
		seq_printf(m, "GUC/SG Intr Enable:\t   %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_GUC_SG_INTR_ENABLE));
		seq_printf(m, "GPM/WGBOXPERF Intr Enable: %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_GPM_WGBOXPERF_INTR_ENABLE));
		seq_printf(m, "Crypto Intr Enable:\t   %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_CRYPTO_RSVD_INTR_ENABLE));
		seq_printf(m, "GUnit/CSME Intr Enable:\t   %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_GUNIT_CSME_INTR_ENABLE));

	} else if (INTEL_GEN(i915) >= 8) {
		seq_printf(m, "Master Interrupt Control:\t%08x\n",
			   intel_uncore_read(uncore, GEN8_MASTER_IRQ));

		for (i = 0; i < 4; i++) {
			seq_printf(m, "GT Interrupt IMR %d:\t%08x\n",
				   i, intel_uncore_read(uncore,
							GEN8_GT_IMR(i)));
			seq_printf(m, "GT Interrupt IIR %d:\t%08x\n",
				   i, intel_uncore_read(uncore,
							GEN8_GT_IIR(i)));
			seq_printf(m, "GT Interrupt IER %d:\t%08x\n",
				   i, intel_uncore_read(uncore,
							GEN8_GT_IER(i)));
		}

	} else if (IS_VALLEYVIEW(i915)) {
		seq_printf(m, "Master IER:\t%08x\n",
			   intel_uncore_read(uncore, VLV_MASTER_IER));

		seq_printf(m, "Render IER:\t%08x\n",
			   intel_uncore_read(uncore, GTIER));
		seq_printf(m, "Render IIR:\t%08x\n",
			   intel_uncore_read(uncore, GTIIR));
		seq_printf(m, "Render IMR:\t%08x\n",
			   intel_uncore_read(uncore, GTIMR));

		seq_printf(m, "PM IER:\t\t%08x\n",
			   intel_uncore_read(uncore, GEN6_PMIER));
		seq_printf(m, "PM IIR:\t\t%08x\n",
			   intel_uncore_read(uncore, GEN6_PMIIR));
		seq_printf(m, "PM IMR:\t\t%08x\n",
			   intel_uncore_read(uncore, GEN6_PMIMR));

	} else if (!HAS_PCH_SPLIT(i915)) {
		seq_printf(m, "Interrupt enable:    %08x\n",
			   intel_uncore_read(uncore, GEN2_IER));
		seq_printf(m, "Interrupt identity:  %08x\n",
			   intel_uncore_read(uncore, GEN2_IIR));
		seq_printf(m, "Interrupt mask:      %08x\n",
			   intel_uncore_read(uncore, GEN2_IMR));
	} else {
		seq_printf(m, "Graphics Interrupt enable:		%08x\n",
			   intel_uncore_read(uncore, GTIER));
		seq_printf(m, "Graphics Interrupt identity:		%08x\n",
			   intel_uncore_read(uncore, GTIIR));
		seq_printf(m, "Graphics Interrupt mask:		%08x\n",
			   intel_uncore_read(uncore, GTIMR));
	}

	if (INTEL_GEN(i915) >= 11) {
		seq_printf(m, "RCS Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_RCS0_RSVD_INTR_MASK));
		seq_printf(m, "BCS Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_BCS_RSVD_INTR_MASK));
		seq_printf(m, "VCS0/VCS1 Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_VCS0_VCS1_INTR_MASK));
		seq_printf(m, "VCS2/VCS3 Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_VCS2_VCS3_INTR_MASK));
		seq_printf(m, "VECS0/VECS1 Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_VECS0_VECS1_INTR_MASK));
		seq_printf(m, "GUC/SG Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_GUC_SG_INTR_MASK));
		seq_printf(m, "GPM/WGBOXPERF Intr Mask: %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_GPM_WGBOXPERF_INTR_MASK));
		seq_printf(m, "Crypto Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_CRYPTO_RSVD_INTR_MASK));
		seq_printf(m, "Gunit/CSME Intr Mask:\t %08x\n",
			   intel_uncore_read(uncore,
					     GEN11_GUNIT_CSME_INTR_MASK));

	} else if (INTEL_GEN(i915) >= 6) {
		for_each_engine(engine, gt, id) {
			seq_printf(m,
				   "Graphics Interrupt mask (%s):	%08x\n",
				   engine->name, ENGINE_READ(engine, RING_IMR));
		}
	}

	intel_runtime_pm_put(uncore->rpm, wakeref);

	return 0;
}
DEFINE_GT_DEBUGFS_ATTRIBUTE(interrupt_info);

void debugfs_gt_register_irq(struct intel_gt *gt, struct dentry *root)
{
	static const struct debugfs_gt_file files[] = {
		{ "interrupt_info", &interrupt_info_fops, NULL },
	};

	intel_gt_debugfs_register_files(root, files, ARRAY_SIZE(files), gt);
}
