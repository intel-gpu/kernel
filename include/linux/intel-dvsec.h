/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INTEL_DVSEC_H
#define INTEL_DVSEC_H

#include <linux/types.h>

#define DVSEC_INTEL_ID_TELEM	2
#define DVSEC_INTEL_ID_WATCHER	3
#define DVSEC_INTEL_ID_CRASHLOG	4

/* Intel DVSEC capability vendor space offsets */
#define INTEL_DVSEC_ENTRIES		0xA
#define INTEL_DVSEC_SIZE		0xB
#define INTEL_DVSEC_TABLE		0xC
#define INTEL_DVSEC_TABLE_BAR(x)	((x) & GENMASK(2, 0))
#define INTEL_DVSEC_TABLE_OFFSET(x)	((x) >> 3)

#define INTEL_DVSEC_ENTRY_SIZE		4

/* DVSEC header */
struct intel_dvsec_header {
	u16	length;
	u16	id;
	u8	num_entries;
	u8	entry_size;
	u8	entry_max;
	u8	tbir;
	u32	offset;
};

enum pmt_quirks {
	/* DVSEC PCI capabilty not preset (must be emulated) */
	PMT_QUIRK_NO_DVSEC	= (1 << 2),
};

struct pmt_platform_info {
	unsigned long quirks;
	struct intel_dvsec_header **capabilities;
};

#endif
