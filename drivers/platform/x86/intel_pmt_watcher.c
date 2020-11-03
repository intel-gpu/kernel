// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Platform Monitoring Aggregator Watcher driver
 *
 * Copyright (c) 2019, Intel Corporation.
 * All Rights Reserved.
 *
 * Authors: "David E. Box" <david.e.box@linux.intel.com>
 */

#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/intel-dvsec.h>

#define DRV_NAME		"pmt_watcher"
#define SMPLR_DEV_PREFIX	"smplr"
#define TRCR_DEV_PREFIX		"trcr"

#define TYPE_TRACER2		0
#define TYPE_SAMPLER2		1
#define TYPE_TRACER1		2
#define TYPE_SAMPLER1		3

/* Watcher sampler mods */
#define MODE_OFF		0
#define MODE_PERIODIC		1
#define MODE_ONESHOT		2
#define MODE_SHARED		3

/* Watcher access types */
#define ACCESS_FUTURE		1
#define ACCESS_BARID		2
#define ACCESS_LOCAL		3

/* Common Header */
#define GUID_OFFSET		0x4
#define BASE_OFFSET		0x8
#define GET_ACCESS(v)		((v) & GENMASK(3, 0))
#define GET_TYPE(v)		(((v) & GENMASK(11, 4)) >> 4)
#define GET_SIZE(v)		(((v) & GENMASK(27, 12)) >> 10)
#define GET_IRQ_EN(v)		((v) & BIT(23))
#define GET_BIR(v)		((v) & 0x7)

/* Common Config fields */
#define GET_MODE(v)		((v) & 0x3)
#define MODE_MASK		GENMASK(1, 0)
#define GET_REQ(v)		((v) & BIT(31))
#define SET_REQ_BIT(v)		((v) | BIT(31))
#define REQUEST_PENDING		1
#define MAX_PERIOD_US		(396 * USEC_PER_SEC)	/* 3600s + 360s = 1.1 hours */

/* Tracer Config - Destination field */
#define TRCR_DEST_TRACEHUB	0
#define TRCR_DEST_OOB		1
#define TRCR_DEST_IRQ		2
#define TRCR_DEST_MASK		GENMASK(5, 2)
#define SET_TRCR_DEST_BITS(v)	((v) << 2)
#define GET_TRCR_DEST(v)	(((v) & TRCR_DEST_MASK) >> 2)

/* Tracer Config - Token field */
#define TRCR_TOKEN_MASK		GENMASK(15, 8)
#define SET_TRCR_TOKEN_BITS(v)	((v) << 8)
#define GET_TRCR_TOKEN(v)	(((v) & TRCR_TOKEN_MASK) >> 8)
#define TRCR_TOKEN_MAX_SIZE	255

/* Tracer Config Offsets */
#define TRCR_CONTROL_OFFSET	0x4
#define TRCR_STREAM_UID_OFFSET	0x8
#define TRCR_VECTOR_OFFSET	0x10

/* Sampler Config Offsets */
#define SMPLR_BUFFER_SIZE_OFFSET	0x4
#define SMPLR_CONTROL_OFFSET		0xC
#define SMPLR_VECTOR_OFFSET		0x10

/*
 * Sampler data size in bytes.
 * s - the size of the sampler data buffer space
 *     given in the config header (pointer field)
 * n - is the number of select vectors
 *
 * Subtract 8 bytes for the size of the timestamp
 */
#define SMPLR_NUM_SAMPLES(s, n)		(((s) - (n) - 8) / 8)

#define NUM_BYTES_DWORD(v)		((v) << 2)

static const char * const sample_mode[] = {
	[MODE_OFF] = "off",
	[MODE_PERIODIC] = "periodic",
	[MODE_ONESHOT] = "oneshot",
	[MODE_SHARED] = "shared"
};

static const char * const tracer_destination[] = {
	[TRCR_DEST_TRACEHUB] = "trace_hub",
	[TRCR_DEST_OOB] = "oob",
	[TRCR_DEST_IRQ] = "irq"
};

static DEFINE_IDA(sampler_devid_ida);
static DEFINE_IDA(tracer_devid_ida);

struct watcher_header {
	u32	access_type;
	u32	watcher_type;
	u32	size;
	bool	irq_support;
	u32	guid;
	u32	base_offset;
	u8	bir;
};

struct watcher_config {
	u32		control;
	u32		period;
	u32		stream_uid;
	unsigned long	*vector;
	unsigned int	vector_size;
	unsigned int	select_limit;
};

struct watcher_endpoint {
	struct watcher_header	header;
	struct watcher_config	config;
	void __iomem		*cfg_base;
	struct cdev		cdev;
	dev_t			devt;
	int			devid;
	struct ida		*ida;
	bool			mode_lock;
	s8			ctrl_offset;
	s8			stream_uid_offset;
	s8			vector_start;

	/* Samplers only */
	unsigned long		smplr_data_start;
	int			smplr_data_size;
};

struct pmt_watcher_priv {
	struct device			*dev;
	struct pci_dev			*parent;
	struct intel_dvsec_header	*dvsec;
	struct watcher_endpoint		ep;
	void __iomem			*disc_table;
};

static inline bool pmt_watcher_is_sampler(struct watcher_endpoint *ep)
{
	return ep->header.watcher_type == TYPE_SAMPLER1 ||
	       ep->header.watcher_type == TYPE_SAMPLER2;
}

static inline bool pmt_watcher_is_tracer(struct watcher_endpoint *ep)
{
	return ep->header.watcher_type == TYPE_TRACER1 ||
	       ep->header.watcher_type == TYPE_TRACER2;
}

static inline bool pmt_watcher_select_limited(struct watcher_endpoint *ep)
{
	return pmt_watcher_is_sampler(ep) ||
	       ep->header.watcher_type == TYPE_TRACER2;
}

static inline bool pmt_watcher_is_type2(struct watcher_endpoint *ep)
{
	return ep->header.watcher_type == TYPE_SAMPLER2 ||
	       ep->header.watcher_type == TYPE_TRACER2;
}

/*
 * I/O
 */
static bool pmt_watcher_request_pending(struct watcher_endpoint *ep)
{
	/*
	 * Read request pending bit into temporary location so we can read the
	 * pending bit without overwriting other settings. If a collection is
	 * still in progress we can't start a new one.
	 */
	u32 control = readl(ep->cfg_base + ep->ctrl_offset);

	return GET_REQ(control) == REQUEST_PENDING;
}

static bool pmt_watcher_in_use(struct watcher_endpoint *ep)
{
	/*
	 * Read request pending bit into temporary location so we can read the
	 * pending bit without overwriting other settings. If a collection is
	 * still in progress we can't start a new one.
	 */
	u32 control = readl(ep->cfg_base + ep->ctrl_offset);

	return GET_MODE(control) != MODE_OFF;
}

static void pmt_watcher_write_ctrl_to_dev(struct watcher_endpoint *ep)
{
	/*
	 * Set the request pending bit and write the control register to
	 * start the collection.
	 */
	u32 control = SET_REQ_BIT(ep->config.control);

	writel(control, ep->cfg_base + ep->ctrl_offset);
}

static void pmt_watcher_write_period_to_dev(struct watcher_endpoint *ep)
{
	/* The period exists on the DWORD opposite the control register */
	writel(ep->config.period, ep->cfg_base + (ep->ctrl_offset ^ 0x4));
}

static void pmt_watcher_write_stream_uid_to_dev(struct watcher_endpoint *ep)
{
	/* nothing to write if stream_uid_offset is negative */
	if (ep->stream_uid_offset < 0)
		return;

	/*
	 * The stream UUID occupies a 64b value, however the second DWORD
	 * is reserved 0 so just write the value as such.
	 */
	writel(ep->config.period, ep->cfg_base + ep->stream_uid_offset);
	writel(0, ep->cfg_base + ep->stream_uid_offset + 4);
}
void
pmt_watcher_write_vector_to_dev_type1(struct watcher_endpoint *ep)
{
	memcpy_toio(ep->cfg_base + ep->vector_start, ep->config.vector,
		    DIV_ROUND_UP(ep->config.vector_size, BITS_PER_BYTE));
}

void
pmt_watcher_write_vector_to_dev_type2(struct watcher_endpoint *ep)
{
	unsigned int index, offset = 0;
	u32 temp;

	for_each_set_bit(index, ep->config.vector, ep->config.vector_size) {
		if (offset & 2) {
			temp |= index << 16;
			writel(temp, ep->cfg_base + ep->vector_start + offset);
		} else {
			temp = index;
		}

		offset += 2;
	}

	if (offset & 2)
		writel(temp, ep->cfg_base + ep->vector_start + offset);
}

void
pmt_watcher_write_vector_to_dev(struct watcher_endpoint *ep)
{
	if (pmt_watcher_is_type2(ep))
		pmt_watcher_write_vector_to_dev_type2(ep);
	else
		pmt_watcher_write_vector_to_dev_type1(ep);
}
/*
 * devfs
 */
static int pmt_watcher_sampler_open(struct inode *inode, struct file *filp)
{
	struct watcher_endpoint *ep;
	struct pci_driver *pci_drv;
	struct pmt_watcher_priv *priv;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ep = container_of(inode->i_cdev, struct watcher_endpoint, cdev);
	priv = container_of(ep, struct pmt_watcher_priv, ep);
	pci_drv = pci_dev_driver(priv->parent);

	if (!pci_drv)
		return -ENODEV;

	filp->private_data = ep;
	get_device(&priv->parent->dev);

	if (!try_module_get(pci_drv->driver.owner)) {
		put_device(&priv->parent->dev);
		return -ENODEV;
	}

	return 0;
}

static int pmt_watcher_sampler_release(struct inode *inode, struct file *filp)
{
	struct watcher_endpoint *ep = filp->private_data;
	struct pmt_watcher_priv *priv;
	struct pci_driver *pci_drv;

	priv = container_of(ep, struct pmt_watcher_priv, ep);
	pci_drv = pci_dev_driver(priv->parent);

	put_device(&priv->parent->dev);
	module_put(pci_drv->driver.owner);

	return 0;
}

static int
pmt_watcher_sampler_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct watcher_endpoint *ep = filp->private_data;
	struct pmt_watcher_priv *priv;
	unsigned long phys = ep->smplr_data_start;
	unsigned long pfn = PFN_DOWN(phys);
	unsigned long vsize = vma->vm_end - vma->vm_start;
	unsigned long psize;

	if ((vma->vm_flags & VM_WRITE) ||
	    (vma->vm_flags & VM_MAYWRITE))
		return -EPERM;

	priv = container_of(ep, struct pmt_watcher_priv, ep);

	if (!ep->header.size) {
		dev_err(priv->dev, "Sampler not accessible\n");
		return -EAGAIN;
	}

	psize = (PFN_UP(ep->smplr_data_start + ep->smplr_data_size) - pfn) *
		PAGE_SIZE;
	if (vsize > psize) {
		dev_err(priv->dev, "Requested mmap size is too large\n");
		return -EINVAL;
	}

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	if (io_remap_pfn_range(vma, vma->vm_start, pfn,
		vsize, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static const struct file_operations pmt_watcher_sampler_fops = {
	.owner =	THIS_MODULE,
	.open =		pmt_watcher_sampler_open,
	.mmap =		pmt_watcher_sampler_mmap,
	.release =	pmt_watcher_sampler_release,
};

/*
 * sysfs
 */
static ssize_t
guid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	return sprintf(buf, "0x%x\n", ep->header.guid);
}
static DEVICE_ATTR_RO(guid);

static ssize_t
mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;
	int i, cnt = 0;

	ep = dev_get_drvdata(dev);

	for (i = 0; i < ARRAY_SIZE(sample_mode); i++) {
		if (i == GET_MODE(ep->config.control))
			cnt += sprintf(buf + cnt, "[%s]", sample_mode[i]);
		else
			cnt += sprintf(buf + cnt, "%s", sample_mode[i]);
		if (i < (ARRAY_SIZE(sample_mode) - 1))
			cnt += sprintf(buf + cnt, " ");
	}

	cnt += sprintf(buf + cnt, "\n");

	return cnt;
}

static ssize_t
mode_store(struct device *dev, struct device_attribute *attr,
	   const char *buf, size_t count)
{
	struct watcher_endpoint *ep;
	int mode;

	ep = dev_get_drvdata(dev);

	mode = sysfs_match_string(sample_mode, buf);
	if (mode < 0)
		return mode;

	/*
	 * Allowable transitions:
	 * Current State     Requested State
	 * -------------     ---------------
	 * DISABLED          PERIODIC or ONESHOT
	 * PERIODIC          DISABLED
	 * ONESHOT           DISABLED
	 * SHARED            DISABLED
	 */
	if ((GET_MODE(ep->config.control) != MODE_OFF) &&
	    (mode != MODE_OFF))
		return -EPERM;

	/* Do not allow user to put device in shared state */
	if (mode == MODE_SHARED)
		return -EPERM;

	/* We cannot change state if there is a request already pending */
	if (pmt_watcher_request_pending(ep))
		return -EBUSY;

	/*
	 * Transition request is valid. Set mode, mode_lock
	 * and execute request.
	 */
	ep->config.control &= ~MODE_MASK;
	ep->config.control |= mode;

	ep->mode_lock = false;

	if (mode != MODE_OFF) {
		ep->mode_lock = true;

		/* Write the period and vector registers to the device */
		pmt_watcher_write_period_to_dev(ep);
		pmt_watcher_write_stream_uid_to_dev(ep);
		pmt_watcher_write_vector_to_dev(ep);
	}

	/* Submit requested changes to device */
	pmt_watcher_write_ctrl_to_dev(ep);

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(mode);

static ssize_t
period_us_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", ep->config.period);
}

static ssize_t
period_us_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct watcher_endpoint *ep;
	u32 period;
	int err;

	ep = dev_get_drvdata(dev);

	if (ep->mode_lock)
		return -EPERM;

	err = kstrtouint(buf, 0, &period);
	if (err)
		return err;

	if (period > MAX_PERIOD_US) {
		dev_err(dev, "Maximum period(us) allowed is %ld\n",
			MAX_PERIOD_US);
		return -EINVAL;
	}

	ep->config.period = period;

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(period_us);

static ssize_t
enable_list_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;
	int err;

	ep = dev_get_drvdata(dev);

	err = bitmap_print_to_pagebuf(true, buf, ep->config.vector,
				      ep->config.vector_size);

	return err ?: strlen(buf);
}

static int
pmt_watcher_write_vector(struct device *dev, struct watcher_endpoint *ep,
			 unsigned long *bit_vector)
{
	/*
	 * Sampler vector select is limited by the size of the sampler
	 * result buffer. Determine if we're exceeding the limit.
	 */
	if (pmt_watcher_select_limited(ep)) {
		int hw = bitmap_weight(bit_vector, ep->config.vector_size);

		if (hw > ep->config.select_limit) {
			dev_err(dev, "Too many bits(%d) selected. Maximum is %d\n",
				hw, ep->config.select_limit);
			return -EINVAL;
		}
	}

	/* Save the vector */
	bitmap_copy(ep->config.vector, bit_vector, ep->config.vector_size);

	return 0;
}

static ssize_t
enable_list_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	struct watcher_endpoint *ep;
	unsigned long *temp;
	int err;

	ep = dev_get_drvdata(dev);

	if (ep->mode_lock)
		return -EPERM;

	/*
	 * Create a temp buffer to store the incoming selection for
	 * validation before saving.
	 */
	temp = bitmap_zalloc(ep->config.vector_size, GFP_KERNEL);
	if (!temp)
		return -ENOMEM;

	/*
	 * Convert and store hexademical input string values into the
	 * temp buffer.
	 */
	err = bitmap_parselist(buf, temp, ep->config.vector_size);

	/* Write new vector to watcher endpoint */
	if (!err)
		err = pmt_watcher_write_vector(dev, ep, temp);

	kfree(temp);

	return err ?: count;
}
static DEVICE_ATTR_RW(enable_list);

static ssize_t
enable_vector_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;
	int err;

	ep = dev_get_drvdata(dev);

	err = bitmap_print_to_pagebuf(false, buf, ep->config.vector,
				      ep->config.vector_size);

	return err ?: strlen(buf);
}

static ssize_t
enable_vector_store(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	struct watcher_endpoint *ep;
	unsigned long *temp;
	int err;

	ep = dev_get_drvdata(dev);

	if (ep->mode_lock)
		return -EPERM;

	/*
	 * Create a temp buffer to store the incoming selection for
	 * validation before saving.
	 */
	temp = bitmap_zalloc(ep->config.vector_size, GFP_KERNEL);
	if (!temp)
		return -ENOMEM;

	/*
	 * Convert and store hexademical input string values into the
	 * temp buffer.
	 */
	err = bitmap_parse(buf, count, temp, ep->config.vector_size);

	/* Write new vector to watcher endpoint */
	if (!err)
		err = pmt_watcher_write_vector(dev, ep, temp);

	kfree(temp);

	return err ?: count;
}
static DEVICE_ATTR_RW(enable_vector);

static ssize_t
enable_id_limit_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", ep->config.vector_size - 1);
}
static DEVICE_ATTR_RO(enable_id_limit);

static ssize_t
select_limit_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	/* vector limit only applies to sampler */
	if (!pmt_watcher_select_limited(ep))
		return sprintf(buf, "%d\n", -1);

	return sprintf(buf, "%u\n", ep->config.select_limit);
}
static DEVICE_ATTR_RO(select_limit);

static ssize_t
size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_sampler(ep))
		return sprintf(buf, "%d\n", -1);

	return sprintf(buf, "%d\n", ep->smplr_data_size);
}
static DEVICE_ATTR_RO(size);

static ssize_t
offset_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_sampler(ep))
		return sprintf(buf, "%d\n", -1);

	return sprintf(buf, "%lu\n", offset_in_page(ep->smplr_data_start));
}
static DEVICE_ATTR_RO(offset);

static ssize_t
destination_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;
	int i, cnt = 0;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_tracer(ep))
		return sprintf(buf, "%d\n", -1);

	for (i = 0; i < ARRAY_SIZE(tracer_destination); i++) {
		if (i == GET_TRCR_DEST(ep->config.control))
			cnt += sprintf(buf + cnt, "[%s]",
				       tracer_destination[i]);
		else
			cnt += sprintf(buf + cnt, "%s",
				       tracer_destination[i]);
		if (i < (ARRAY_SIZE(tracer_destination) - 1))
			cnt += sprintf(buf + cnt, " ");
	}

	cnt += sprintf(buf + cnt, "\n");

	return cnt;
}

static ssize_t
destination_store(struct device *dev, struct device_attribute *attr,
		  const char *buf, size_t count)
{
	struct watcher_endpoint *ep;
	int ret;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_tracer(ep))
		return -EINVAL;

	if (ep->mode_lock)
		return -EPERM;

	ret = sysfs_match_string(tracer_destination, buf);
	if (ret < 0)
		return ret;

	ep->config.control &= ~TRCR_DEST_MASK;
	ep->config.control |= SET_TRCR_DEST_BITS(ret);

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(destination);

static ssize_t
token_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_tracer(ep))
		return sprintf(buf, "%d\n", -1);

	return sprintf(buf, "%lu\n", GET_TRCR_DEST(ep->config.control));
}

static ssize_t
token_store(struct device *dev, struct device_attribute *attr,
	    const char *buf, size_t count)
{
	struct watcher_endpoint *ep;
	u32 token;
	int result;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_tracer(ep))
		return -EINVAL;

	if (ep->mode_lock)
		return -EPERM;

	result = kstrtouint(buf, 0, &token);
	if (result)
		return result;

	if (token > TRCR_TOKEN_MAX_SIZE)
		return -EINVAL;

	ep->config.control &= ~TRCR_TOKEN_MASK;
	ep->config.control |= SET_TRCR_TOKEN_BITS(token);

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(token);

static ssize_t
stream_uid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct watcher_endpoint *ep;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_tracer(ep) || ep->stream_uid_offset < 0)
		return sprintf(buf, "%d\n", -1);

	return sprintf(buf, "0x%08x\n", ep->config.stream_uid);
}

static ssize_t
stream_uid_store(struct device *dev, struct device_attribute *attr,
	    const char *buf, size_t count)
{
	struct watcher_endpoint *ep;
	u32 stream_uid;
	int result;

	ep = dev_get_drvdata(dev);

	if (!pmt_watcher_is_tracer(ep) || ep->stream_uid_offset < 0)
		return -EINVAL;

	if (ep->mode_lock)
		return -EPERM;

	result = kstrtouint(buf, 0, &stream_uid);
	if (result)
		return result;

	ep->config.stream_uid = stream_uid;

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(stream_uid);

static struct attribute *pmt_watcher_attrs[] = {
	&dev_attr_guid.attr,
	&dev_attr_mode.attr,
	&dev_attr_period_us.attr,
	&dev_attr_enable_list.attr,
	&dev_attr_enable_vector.attr,
	&dev_attr_enable_id_limit.attr,
	&dev_attr_select_limit.attr,
	&dev_attr_size.attr,
	&dev_attr_offset.attr,
	&dev_attr_destination.attr,
	&dev_attr_token.attr,
	&dev_attr_stream_uid.attr,
	NULL
};
ATTRIBUTE_GROUPS(pmt_watcher);

static struct class pmt_watcher_class = {
	.name = "pmt_watcher",
	.owner = THIS_MODULE,
	.dev_groups = pmt_watcher_groups,
};

/*
 * initialization
 */
static int pmt_watcher_make_dev(struct pmt_watcher_priv *priv)
{
	struct watcher_endpoint *ep = &priv->ep;
	struct device *dev;
	const char *name;
	int err;

	err = alloc_chrdev_region(&ep->devt, 0, 1, DRV_NAME);
	if (err < 0) {
		dev_err(priv->dev, "alloc_chrdev_region err: %d\n", err);
		return err;
	}

	/* Create a character device for Samplers */
	if (pmt_watcher_is_sampler(ep)) {
		cdev_init(&ep->cdev, &pmt_watcher_sampler_fops);

		err = cdev_add(&ep->cdev, ep->devt, 1);
		if (err) {
			dev_err(priv->dev, "Could not add char dev\n");
			return err;
		}

		name = SMPLR_DEV_PREFIX;
	} else
		name = TRCR_DEV_PREFIX;

	dev = device_create(&pmt_watcher_class, priv->dev, ep->devt, ep,
			    "%s%d", name, ep->devid);

	if (IS_ERR(dev)) {
		dev_err(priv->dev, "Could not create device node\n");
		cdev_del(&ep->cdev);
	}

	return PTR_ERR_OR_ZERO(dev);
}

static int
pmt_watcher_create_endpoint(struct pmt_watcher_priv *priv)
{
	struct watcher_endpoint *ep = &priv->ep;
	int vector_sz_in_bytes = ep->header.size - ep->vector_start;
	struct resource res;

	res.start = pci_resource_start(priv->parent, ep->header.bir) +
		    ep->header.base_offset;
	res.end = res.start + ep->header.size - 1;
	res.flags = IORESOURCE_MEM;

	ep->cfg_base = devm_ioremap_resource(priv->dev, &res);
	if (IS_ERR(ep->cfg_base))
		return PTR_ERR(ep->cfg_base);

	/*
	 * If there is already some request that is stuck in the hardware
	 * then we will need to wait for it to be cleared before we can
	 * bring up the device.
	 */
	if (pmt_watcher_request_pending(ep))
		return -EBUSY;

	/*
	 * Verify we have sufficient space to store the sample IDs or
	 * bit vector needed to select sample IDs.
	 */
	if (vector_sz_in_bytes < 2 || vector_sz_in_bytes > ep->header.size)
		return -EINVAL;

	/*
	 * Determine the appropriate size of the vector in bits so that
	 * the bitmap can be allocated.
	 */
	if (pmt_watcher_is_type2(ep)) {
		ep->config.vector_size = 1UL << 16;
		ep->config.select_limit = vector_sz_in_bytes / 2;
	} else {
		ep->config.vector_size = vector_sz_in_bytes * BITS_PER_BYTE;
		ep->config.select_limit = UINT_MAX;
	}

	if (pmt_watcher_is_sampler(ep)) {
		unsigned int sample_limit;

		/*
		 * For sampler only, get the physical address and size of
		 * the result buffer for the mmap as well as the vector
		 * select limit for bounds checking.
		 */
		ep->smplr_data_start =
			pci_resource_start(priv->parent, ep->header.bir) +
					   readl(ep->cfg_base);
		ep->smplr_data_size =
			NUM_BYTES_DWORD(readb(ep->cfg_base +
					SMPLR_BUFFER_SIZE_OFFSET));

		/*
		 * SMPLR_NUM_SAMPLES returns bytes divided by 8 to get number
		 * of qwords which is the unit of sampling. Select_limit is
		 * the maximum allowable hweight for the select vector
		 */
		sample_limit = SMPLR_NUM_SAMPLES(ep->smplr_data_size,
				                 vector_sz_in_bytes);

		if (sample_limit < ep->config.select_limit)
			ep->config.select_limit = sample_limit;
	}

	ep->config.vector = bitmap_zalloc(ep->config.vector_size, GFP_KERNEL);
	if (!ep->config.vector)
		return -ENOMEM;

	/*
	 * Set mode to "Disabled" to clean up any state that may still be
	 * floating around in the registers. If it looks like an out-of-band
	 * entity might be using the part set the mode to shared to indicate
	 * that we have not taken full control of the device yet.
	 */
	if (!pmt_watcher_in_use(ep))
		pmt_watcher_write_ctrl_to_dev(ep);
	else
		ep->config.control = MODE_SHARED;

	return 0;
}

static void
pmt_watcher_populate_header(void __iomem *disc_offset,
			    struct watcher_header *header)
{
	header->access_type = GET_ACCESS(readb(disc_offset));
	header->watcher_type = GET_TYPE(readb(disc_offset));
	header->size = GET_SIZE(readl(disc_offset));
	header->irq_support = GET_IRQ_EN(readl(disc_offset));
	header->guid = readl(disc_offset + GUID_OFFSET);
	header->base_offset = readl(disc_offset + BASE_OFFSET);

	/*
	 * For non-local access types the lower 3 bits of base offset
	 * contains the index of the base address register where the
	 * telemetry can be found.
	 */
	header->bir = GET_BIR(header->base_offset);
	header->base_offset ^= header->bir;
}

static int pmt_watcher_probe(struct platform_device *pdev)
{
	struct pmt_watcher_priv *priv;
	struct watcher_endpoint *ep;
	int err;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ep = &priv->ep;

	platform_set_drvdata(pdev, priv);
	priv->dev = &pdev->dev;
	priv->parent  = to_pci_dev(priv->dev->parent);

	priv->dvsec = dev_get_platdata(&pdev->dev);
	if (!priv->dvsec) {
		dev_err(&pdev->dev, "Platform data not found\n");
		return -ENODEV;
	}

	priv->disc_table = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->disc_table))
		return PTR_ERR(priv->disc_table);

	pmt_watcher_populate_header(priv->disc_table, &priv->ep.header);

	/* Local access and BARID only for now */
	switch (ep->header.access_type) {
	case ACCESS_LOCAL:
		if (ep->header.bir) {
			dev_err(&pdev->dev,
				"Unsupported BAR index %d for access type %d\n",
				ep->header.bir, ep->header.access_type);
			return -EINVAL;
		}
		/* Fall Through */
	case ACCESS_BARID:
		break;
	default:
		dev_err(&pdev->dev, "Unsupported access type %d\n",
			ep->header.access_type);
		return -EINVAL;
	}

	if (pmt_watcher_is_tracer(ep)) {
		ep->ida = &tracer_devid_ida;
		ep->ctrl_offset = TRCR_CONTROL_OFFSET;
		ep->vector_start = TRCR_VECTOR_OFFSET;
		ep->stream_uid_offset = TRCR_STREAM_UID_OFFSET;
	} else {
		ep->ida = &sampler_devid_ida;
		ep->ctrl_offset = SMPLR_CONTROL_OFFSET;
		ep->vector_start = SMPLR_VECTOR_OFFSET;
		ep->stream_uid_offset = -1;
	}

	/* Add quirks related to TGL part */
	if (priv->parent->device == 0x9a0d) {
		/* tracer for TGL does not have support for stream UID */
		ep->stream_uid_offset = -1;
		/* strip section that would have been stream UID */
		if (pmt_watcher_is_tracer(ep))
			ep->vector_start -= 8;
		/* account for period and control being swapped */
		ep->ctrl_offset -= 4;

		/*
		 * Add offset for watcher type to account for type1 vs
		 * type2 values.
		 */
		ep->header.watcher_type += TYPE_TRACER1;
	}

	err = pmt_watcher_create_endpoint(priv);
	if (err)
		return err;

	ep->devid = ida_simple_get(ep->ida, 0, 0, GFP_KERNEL);
	if (ep->devid < 0)
		return ep->devid;

	err = pmt_watcher_make_dev(priv);
	if (err) {
		ida_simple_remove(ep->ida, ep->devid);
		return err;
	}

	return 0;
}

static int pmt_watcher_remove(struct platform_device *pdev)
{
	struct pmt_watcher_priv *priv;
	struct watcher_endpoint *ep;

	priv = (struct pmt_watcher_priv *)platform_get_drvdata(pdev);
	ep = &priv->ep;

	device_destroy(&pmt_watcher_class, ep->devt);
	if (pmt_watcher_is_sampler(ep))
		cdev_del(&ep->cdev);

	unregister_chrdev_region(ep->devt, 1);
	ida_simple_remove(ep->ida, ep->devid);

	return 0;
}

static struct platform_driver pmt_watcher_driver = {
	.driver = {
		.name   = DRV_NAME,
	},
	.probe  = pmt_watcher_probe,
	.remove = pmt_watcher_remove,
};

static int __init pmt_watcher_init(void)
{
	int ret = class_register(&pmt_watcher_class);

	if (ret)
		return ret;

	ret = platform_driver_register(&pmt_watcher_driver);
	if (ret) {
		class_unregister(&pmt_watcher_class);
		return ret;
	}

	return 0;
}

static void __exit pmt_watcher_exit(void)
{
	platform_driver_unregister(&pmt_watcher_driver);
	class_unregister(&pmt_watcher_class);
	ida_destroy(&sampler_devid_ida);
	ida_destroy(&tracer_devid_ida);
}

module_init(pmt_watcher_init);
module_exit(pmt_watcher_exit);

MODULE_AUTHOR("David E. Box <david.e.box@linux.intel.com>");
MODULE_DESCRIPTION("Intel PMT Telemetry driver");
MODULE_ALIAS("platform:" DRV_NAME);
MODULE_LICENSE("GPL v2");
