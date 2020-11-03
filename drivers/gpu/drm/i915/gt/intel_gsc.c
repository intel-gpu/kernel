// SPDX-License-Identifier: MIT
/*
 * Copyright(c) 2019-2020, Intel Corporation. All rights reserved.
 */

#include <linux/platform_device.h>
#include <linux/mfd/core.h>
#include <linux/irq.h>
#include "i915_reg.h"
#include "i915_drv.h"
#include "gt/intel_gt.h"
#include "intel_gsc.h"

#define GSC_BAR_LENGTH  0x00000FFC

static void gsc_irq_mask(struct irq_data *d)
{
	/* generic irq handling */
}

static void gsc_irq_unmask(struct irq_data *d)
{
	/* generic irq handling */
}

static struct irq_chip gsc_irq_chip = {
	.name = "gsc_irq_chip",
	.irq_mask = gsc_irq_mask,
	.irq_unmask = gsc_irq_unmask,
};

static int gsc_irq_init(struct drm_i915_private *dev_priv, int irq)
{
	irq_set_chip_and_handler_name(irq, &gsc_irq_chip,
				      handle_simple_irq, "gsc_irq_handler");

	return irq_set_chip_data(irq, dev_priv);
}

/* gsc (graphics system controller) resources */
static const struct resource gsc_resources[] = {
	DEFINE_RES_IRQ_NAMED(0, "gsc-irq"),
	DEFINE_RES_MEM_NAMED(GEN12_GSC_HECI1_BASE,
			     GSC_BAR_LENGTH,
			     "gsc-mmio"),
};

/* gscfi (graphics system controller firmware interface) resources */
static const struct resource gscfi_resources[] = {
	DEFINE_RES_IRQ_NAMED(0, "gscfi-irq"),
	DEFINE_RES_MEM_NAMED(GEN12_GSC_HECI2_BASE,
			     GSC_BAR_LENGTH,
			     "gscfi-mmio"),
};

static struct mfd_cell intel_gsc_cell[] = {
	{
		.id = 0,
		.name = "mei-gsc",
		.num_resources = ARRAY_SIZE(gsc_resources),
		.resources  = gsc_resources,
		.pm_runtime_no_callbacks = true,
	},
	{
		.id = 1,
		.name = "mei-gscfi",
		.num_resources = ARRAY_SIZE(gscfi_resources),
		.resources  = gscfi_resources,
		.pm_runtime_no_callbacks = true,
	}
};

static void intel_gsc_destroy_one(struct intel_gsc_intf *intf)
{
	if (intf->irq >= 0)
		irq_free_desc(intf->irq);
	intf->irq = -1;
}

static void intel_gsc_init_one(struct drm_i915_private *dev_priv,
			       struct intel_gsc_intf *intf,
			       unsigned int intf_id)
{
	struct pci_dev *pdev = dev_priv->drm.pdev;
	int ret;

	dev_dbg(&pdev->dev, "init gsc one with id %d\n", intf_id);
	intf->irq = irq_alloc_desc(0);
	if (intf->irq < 0) {
		dev_err(&pdev->dev, "gsc irq error %d\n", intf->irq);
		return;
	}

	ret = gsc_irq_init(dev_priv, intf->irq);
	if (ret < 0) {
		dev_err(&pdev->dev, "gsc irq init failed %d\n", ret);
		goto fail;
	}

	ret = mfd_add_devices(&pdev->dev, PLATFORM_DEVID_AUTO,
			      &intel_gsc_cell[intf_id], 1,
			      &pdev->resource[0], intf->irq, NULL);
	if (ret < 0) {
		dev_err(&pdev->dev, "cell creation failed\n");
		goto fail;
	}

	intf->id = intf_id;

	dev_dbg(&pdev->dev, "gsc init one done\n");
	return;
fail:
	intel_gsc_destroy_one(intf);
}

static void intel_gsc_irq_handler(struct intel_gt *gt, unsigned int intf_id)
{
	int ret;

	if (intf_id >= INTEL_GSC_NUM_INTERFACES)
		return;

	if (!HAS_GSC(gt->i915))
		return;

	if (gt->gsc.intf[intf_id].irq <= 0) {
		DRM_ERROR_RATELIMITED("error handling GSC irq: irq not set");
		return;
	}

	ret = generic_handle_irq(gt->gsc.intf[intf_id].irq);
	if (ret)
		DRM_ERROR_RATELIMITED("error handling GSC irq: %d\n", ret);
}

void gsc_irq_handler(struct intel_gt *gt, u32 iir)
{
	if (iir & GSC_IRQ_INTF(0))
		intel_gsc_irq_handler(gt, 0);
	if (iir & GSC_IRQ_INTF(1))
		intel_gsc_irq_handler(gt, 1);
}

void intel_gsc_init(struct intel_gsc *gsc, struct drm_i915_private *dev_priv)
{
	unsigned int i;

	if (!HAS_GSC(dev_priv))
		return;

	for (i = 0; i < INTEL_GSC_NUM_INTERFACES; i++)
		intel_gsc_init_one(dev_priv, &gsc->intf[i], i);
}

void intel_gsc_fini(struct intel_gsc *gsc)
{
	struct intel_gt *gt = gsc_to_gt(gsc);
	unsigned int i;

	if (!HAS_GSC(gt->i915))
		return;

	for (i = 0; i < INTEL_GSC_NUM_INTERFACES; i++)
		intel_gsc_destroy_one(&gsc->intf[i]);
}
