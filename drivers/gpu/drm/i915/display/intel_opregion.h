/*
 * Copyright © 2008-2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#ifndef _INTEL_OPREGION_H_
#define _INTEL_OPREGION_H_

#include <linux/workqueue.h>
#include <linux/pci.h>

struct drm_i915_private;
struct intel_encoder;

struct opregion_header;
struct opregion_acpi;
struct opregion_swsci;
struct opregion_asle;

struct intel_opregion {
	struct opregion_header *header;
	struct opregion_acpi *acpi;
	struct opregion_swsci *swsci;
	u32 swsci_gbda_sub_functions;
	u32 swsci_sbcb_sub_functions;
	struct opregion_asle *asle;
	void *rvda;
	void *vbt_firmware;
	const void *vbt;
	u32 vbt_size;
	u32 *lid_state;
	struct work_struct asle_work;
	struct notifier_block acpi_notifier;
};

#define OPREGION_SIZE            (8 * 1024)

#define CPD_SIGNATURE "$CPD"                  /* CPD Signature */
#define NUM_CPD_BYTES 4
#define PCI_IMAGE_LENGTH_OFFSET 0x10
#define PCI_CODE_TYPE_OFFSET 0x14
#define PCI_LAST_IMAGE_INDICATOR_OFFSET 0x15
#define LAST_IMG_INDICATOR 0x80
#define OPROM_IMAGE_MAGIC 0xAA55       /* Little Endian */
#define OPROM_CSS_CODE_TYPE 0xF0
#define OPROM_BYTE_BOUNDARY 512        /* OPROM image sizes are indicated in 512 byte boundaries */
#define OPROM_INITIAL_READ_SIZE 60     /* Read 60 bytes to compute the Img Len from PCI structure */

union oprom_header {
	u32 data;
	struct {
		u16 signature;  /* Offset[0x0]: Header 0x55 0xAA */
		u8 sizein512bytes;
		u8 reserved;
	};
};

struct expansion_rom_header {
	union oprom_header header;      /* Offset[0x0]: Oprom Header */
	u16 vbiospostoffset;    /* Offset[0x4]: pointer to VBIOS entry point */
	u8 resvd[0x12];
	u16 pcistructoffset;    /* Offset[0x18]: Contains pointer PCI Data Structure */
	u16 opregion_base;      /* Offset[0x1A]: Offset to Opregion Base start */
};

#ifdef CONFIG_ACPI

int intel_opregion_setup(struct drm_i915_private *dev_priv);

void intel_opregion_register(struct drm_i915_private *dev_priv);
void intel_opregion_unregister(struct drm_i915_private *dev_priv);

void intel_opregion_resume(struct drm_i915_private *dev_priv);
void intel_opregion_suspend(struct drm_i915_private *dev_priv,
			    pci_power_t state);

void intel_opregion_asle_intr(struct drm_i915_private *dev_priv);
int intel_opregion_notify_encoder(struct intel_encoder *intel_encoder,
				  bool enable);
int intel_opregion_notify_adapter(struct drm_i915_private *dev_priv,
				  pci_power_t state);
int intel_opregion_get_panel_type(struct drm_i915_private *dev_priv);

#else /* CONFIG_ACPI*/

static inline int intel_opregion_setup(struct drm_i915_private *dev_priv)
{
	return 0;
}

static inline void intel_opregion_register(struct drm_i915_private *dev_priv)
{
}

static inline void intel_opregion_unregister(struct drm_i915_private *dev_priv)
{
}

static inline void intel_opregion_resume(struct drm_i915_private *dev_priv)
{
}

static inline void intel_opregion_suspend(struct drm_i915_private *dev_priv,
					  pci_power_t state)
{
}

static inline void intel_opregion_asle_intr(struct drm_i915_private *dev_priv)
{
}

static inline int
intel_opregion_notify_encoder(struct intel_encoder *intel_encoder, bool enable)
{
	return 0;
}

static inline int
intel_opregion_notify_adapter(struct drm_i915_private *dev, pci_power_t state)
{
	return 0;
}

static inline int intel_opregion_get_panel_type(struct drm_i915_private *dev)
{
	return -ENODEV;
}

#endif /* CONFIG_ACPI */
int intel_oprom_verify_signature(u32 **opreg, u16 *opreg_size,
				 struct drm_i915_private *i915);
#endif
