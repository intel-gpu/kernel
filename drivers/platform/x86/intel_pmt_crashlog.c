// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Platform Monitoring Crashlog driver
 *
 * Copyright (c) 2020, Intel Corporation.
 * All Rights Reserved.
 *
 * Authors: "Alexander Duyck" <alexander.h.duyck@linux.intel.com>
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

#define DRV_NAME		"pmt_crashlog"

/* Crashlog access types */
#define ACCESS_FUTURE		1
#define ACCESS_BARID		2
#define ACCESS_LOCAL		3

/* Crashlog discovery header types */
#define CRASH_TYPE_OOBMSM	1

/* Control Flags */
#define CRASHLOG_FLAG_DISABLE	BIT(27)
#define CRASHLOG_FLAG_CLEAR	BIT(28)
#define CRASHLOG_FLAG_EXECUTE	BIT(29)
#define CRASHLOG_FLAG_COMPLETE	BIT(31)
#define CRASHLOG_FLAG_MASK	GENMASK(31, 28)

/* Common Header */
#define CONTROL_OFFSET		0x0
#define GUID_OFFSET		0x4
#define BASE_OFFSET		0x8
#define SIZE_OFFSET		0xC
#define GET_ACCESS(v)		((v) & GENMASK(3, 0))
#define GET_TYPE(v)		(((v) & GENMASK(7, 4)) >> 4)
#define GET_VERSION(v)		(((v) & GENMASK(19, 16)) >> 16)

#define GET_ADDRESS(v)		((v) & GENMASK(31, 3))
#define GET_BIR(v)		((v) & GENMASK(2, 0))

static DEFINE_IDA(crashlog_devid_ida);

struct crashlog_header {
	u32	base_offset;
	u32	size;
	u32	guid;
	u8	bir;
	u8	access_type;
	u8	crash_type;
	u8	version;
};

struct crashlog_endpoint {
	struct crashlog_header	header;
	unsigned long		crashlog_data;
	size_t			crashlog_data_size;
	struct cdev		cdev;
	dev_t			devt;
	int			devid;
	struct ida		*ida;
};

struct pmt_crashlog_priv {
	struct device			*dev;
	struct pci_dev			*parent;
	struct intel_dvsec_header	*dvsec;
	struct crashlog_endpoint	ep;
	void __iomem			*disc_table;
};

/*
 * I/O
 */
static bool pmt_crashlog_complete(struct crashlog_endpoint *ep)
{
	struct pmt_crashlog_priv *priv = container_of(ep,
						      struct pmt_crashlog_priv,
						      ep);
	u32 control = readl(priv->disc_table + CONTROL_OFFSET);

	/* return current value of the crashlog complete flag */
	return !!(control & CRASHLOG_FLAG_COMPLETE);
}

static bool pmt_crashlog_disabled(struct crashlog_endpoint *ep)
{
	struct pmt_crashlog_priv *priv = container_of(ep,
						      struct pmt_crashlog_priv,
						      ep);
	u32 control = readl(priv->disc_table + CONTROL_OFFSET);

	/* return current value of the crashlog disabled flag */
	return !!(control & CRASHLOG_FLAG_DISABLE);
}

static void pmt_crashlog_set_disable(struct crashlog_endpoint *ep, bool disable)
{
	struct pmt_crashlog_priv *priv = container_of(ep,
						      struct pmt_crashlog_priv,
						      ep);
	u32 control = readl(priv->disc_table + CONTROL_OFFSET);

	/* clear control bits */
	control &= ~(CRASHLOG_FLAG_MASK | CRASHLOG_FLAG_DISABLE);
	if (disable)
		control |= CRASHLOG_FLAG_DISABLE;

	writel(control, priv->disc_table + CONTROL_OFFSET);
}

static void pmt_crashlog_set_clear(struct crashlog_endpoint *ep)
{
	struct pmt_crashlog_priv *priv = container_of(ep,
						      struct pmt_crashlog_priv,
						      ep);
	u32 control = readl(priv->disc_table + CONTROL_OFFSET);

	/* clear control bits */
	control &= ~CRASHLOG_FLAG_MASK;
	control |= CRASHLOG_FLAG_CLEAR;

	writel(control, priv->disc_table + CONTROL_OFFSET);
}

static void pmt_crashlog_set_execute(struct crashlog_endpoint *ep)
{
	struct pmt_crashlog_priv *priv = container_of(ep,
						      struct pmt_crashlog_priv,
						      ep);
	u32 control = readl(priv->disc_table + CONTROL_OFFSET);

	/* clear control bits */
	control &= ~CRASHLOG_FLAG_MASK;
	control |= CRASHLOG_FLAG_EXECUTE;

	writel(control, priv->disc_table + CONTROL_OFFSET);
}

/*
 * devfs
 */
static int pmt_crashlog_open(struct inode *inode, struct file *filp)
{
	struct crashlog_endpoint *ep;
	struct pci_driver *pci_drv;
	struct pmt_crashlog_priv *priv;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ep = container_of(inode->i_cdev, struct crashlog_endpoint, cdev);
	priv = container_of(ep, struct pmt_crashlog_priv, ep);
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

static int pmt_crashlog_release(struct inode *inode, struct file *filp)
{
	struct crashlog_endpoint *ep = filp->private_data;
	struct pmt_crashlog_priv *priv;
	struct pci_driver *pci_drv;

	priv = container_of(ep, struct pmt_crashlog_priv, ep);
	pci_drv = pci_dev_driver(priv->parent);

	put_device(&priv->parent->dev);
	module_put(pci_drv->driver.owner);

	return 0;
}

static int
pmt_crashlog_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct crashlog_endpoint *ep = filp->private_data;
	struct pmt_crashlog_priv *priv;
	unsigned long phys = ep->crashlog_data;
	unsigned long pfn = PFN_DOWN(phys);
	unsigned long vsize = vma->vm_end - vma->vm_start;
	unsigned long psize;

	if ((vma->vm_flags & VM_WRITE) ||
	    (vma->vm_flags & VM_MAYWRITE))
		return -EPERM;

	priv = container_of(ep, struct pmt_crashlog_priv, ep);

	if (!ep->crashlog_data_size) {
		dev_err(priv->dev, "Crashlog data not accessible\n");
		return -EAGAIN;
	}

	psize = (PFN_UP(ep->crashlog_data + ep->crashlog_data_size) - pfn) *
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

static const struct file_operations pmt_crashlog_fops = {
	.owner =	THIS_MODULE,
	.open =		pmt_crashlog_open,
	.mmap =		pmt_crashlog_mmap,
	.release =	pmt_crashlog_release,
};

/*
 * sysfs
 */
static ssize_t
guid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct crashlog_endpoint *ep;

	ep = dev_get_drvdata(dev);

	return sprintf(buf, "0x%x\n", ep->header.guid);
}
static DEVICE_ATTR_RO(guid);

static ssize_t size_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct crashlog_endpoint *ep;

	ep = dev_get_drvdata(dev);

	return sprintf(buf, "0x%lu\n", ep->crashlog_data_size);
}
static DEVICE_ATTR_RO(size);

static ssize_t
offset_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct crashlog_endpoint *ep;

	ep = dev_get_drvdata(dev);

	return sprintf(buf, "%lu\n", offset_in_page(ep->crashlog_data));
}
static DEVICE_ATTR_RO(offset);

static ssize_t
enable_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct crashlog_endpoint *ep;
	int enabled;

	ep = dev_get_drvdata(dev);
	enabled = !pmt_crashlog_disabled(ep);

	return sprintf(buf, "%d\n", enabled);
}

static ssize_t
enable_store(struct device *dev, struct device_attribute *attr,
	    const char *buf, size_t count)
{
	struct crashlog_endpoint *ep;
	bool enabled;
	int result;

	ep = dev_get_drvdata(dev);

	result = kstrtobool(buf, &enabled);
	if (result)
		return result;

	pmt_crashlog_set_disable(ep, !enabled);

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(enable);

static ssize_t
trigger_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct crashlog_endpoint *ep;
	int trigger;

	ep = dev_get_drvdata(dev);
	trigger = pmt_crashlog_complete(ep);

	return sprintf(buf, "%d\n", trigger);
}

static ssize_t
trigger_store(struct device *dev, struct device_attribute *attr,
	    const char *buf, size_t count)
{
	struct crashlog_endpoint *ep;
	bool trigger;
	int result;

	ep = dev_get_drvdata(dev);

	result = kstrtobool(buf, &trigger);
	if (result)
		return result;

	if (trigger) {
		/* we cannot trigger a new crash if one is still pending */
		if (pmt_crashlog_complete(ep))
			return -EEXIST;

		/* if device is currently disabled, return busy */
		if (pmt_crashlog_disabled(ep))
			return -EBUSY;

		pmt_crashlog_set_execute(ep);
	} else {
		pmt_crashlog_set_clear(ep);
	}

	return strnlen(buf, count);
}
static DEVICE_ATTR_RW(trigger);

static struct attribute *pmt_crashlog_attrs[] = {
	&dev_attr_guid.attr,
	&dev_attr_size.attr,
	&dev_attr_offset.attr,
	&dev_attr_enable.attr,
	&dev_attr_trigger.attr,
	NULL
};
ATTRIBUTE_GROUPS(pmt_crashlog);

static struct class pmt_crashlog_class = {
	.name = "pmt_crashlog",
	.owner = THIS_MODULE,
	.dev_groups = pmt_crashlog_groups,
};

/*
 * initialization
 */
static int pmt_crashlog_make_dev(struct pmt_crashlog_priv *priv)
{
	struct crashlog_endpoint *ep = &priv->ep;
	struct device *dev;
	int err;

	err = alloc_chrdev_region(&ep->devt, 0, 1, DRV_NAME);
	if (err < 0) {
		dev_err(priv->dev, "alloc_chrdev_region err: %d\n", err);
		return err;
	}

	/* Create a character device for Samplers */
	cdev_init(&ep->cdev, &pmt_crashlog_fops);

	err = cdev_add(&ep->cdev, ep->devt, 1);
	if (err) {
		dev_err(priv->dev, "Could not add char dev\n");
		return err;
	}

	dev = device_create(&pmt_crashlog_class, priv->dev, ep->devt, ep,
			    "%s%d", "crashlog", ep->devid);

	if (IS_ERR(dev)) {
		dev_err(priv->dev, "Could not create device node\n");
		cdev_del(&ep->cdev);
	}

	return PTR_ERR_OR_ZERO(dev);
}

static void
pmt_crashlog_populate_header(void __iomem *disc_offset,
			     struct crashlog_header *header)
{
	u32 discovery_header = readl(disc_offset);

	header->access_type = GET_ACCESS(discovery_header);
	header->crash_type = GET_TYPE(discovery_header);
	header->version = GET_VERSION(discovery_header);
	header->guid = readl(disc_offset + GUID_OFFSET);
	header->base_offset = readl(disc_offset + BASE_OFFSET);

	/*
	 * For non-local access types the lower 3 bits of base offset
	 * contains the index of the base address register where the
	 * telemetry can be found.
	 */
	header->bir = GET_BIR(header->base_offset);
	header->base_offset ^= header->bir;

	/* Size is measured in DWORDs */
	header->size = readl(disc_offset + SIZE_OFFSET);
}

static int pmt_crashlog_probe(struct platform_device *pdev)
{
	struct pmt_crashlog_priv *priv;
	struct crashlog_endpoint *ep;
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

	pmt_crashlog_populate_header(priv->disc_table, &priv->ep.header);

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

	if (ep->header.crash_type != CRASH_TYPE_OOBMSM) {
		dev_err(&pdev->dev, "Unsupported crashlog header type %d\n",
			ep->header.crash_type);
		return -EINVAL;
	}

	if (ep->header.version != 0) {
		dev_err(&pdev->dev, "Unsupported version value %d\n",
			ep->header.version);
		return -EINVAL;
	}

	ep->ida = &crashlog_devid_ida;
	ep->crashlog_data = pci_resource_start(priv->parent, ep->header.bir) +
			    ep->header.base_offset;
	ep->crashlog_data_size = ep->header.size * 4;

	ep->devid = ida_simple_get(ep->ida, 0, 0, GFP_KERNEL);
	if (ep->devid < 0)
		return ep->devid;

	err = pmt_crashlog_make_dev(priv);
	if (err) {
		ida_simple_remove(ep->ida, ep->devid);
		return err;
	}

	return 0;
}

static int pmt_crashlog_remove(struct platform_device *pdev)
{
	struct pmt_crashlog_priv *priv;
	struct crashlog_endpoint *ep;

	priv = (struct pmt_crashlog_priv *)platform_get_drvdata(pdev);
	ep = &priv->ep;

	device_destroy(&pmt_crashlog_class, ep->devt);
	cdev_del(&ep->cdev);

	unregister_chrdev_region(ep->devt, 1);
	ida_simple_remove(ep->ida, ep->devid);

	return 0;
}

static struct platform_driver pmt_crashlog_driver = {
	.driver = {
		.name   = DRV_NAME,
	},
	.probe  = pmt_crashlog_probe,
	.remove = pmt_crashlog_remove,
};

static int __init pmt_crashlog_init(void)
{
	int ret = class_register(&pmt_crashlog_class);

	if (ret)
		return ret;

	ret = platform_driver_register(&pmt_crashlog_driver);
	if (ret) {
		class_unregister(&pmt_crashlog_class);
		return ret;
	}

	return 0;
}

static void __exit pmt_crashlog_exit(void)
{
	platform_driver_unregister(&pmt_crashlog_driver);
	class_unregister(&pmt_crashlog_class);
	ida_destroy(&crashlog_devid_ida);
}

module_init(pmt_crashlog_init);
module_exit(pmt_crashlog_exit);

MODULE_AUTHOR("Alexander Duyck <alexander.h.duyck@linux.intel.com>");
MODULE_DESCRIPTION("Intel PMT Crashlog driver");
MODULE_ALIAS("platform:" DRV_NAME);
MODULE_LICENSE("GPL v2");
