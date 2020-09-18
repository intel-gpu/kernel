// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2019-2020, Intel Corporation. All rights reserved.
 *
 * Intel Management Engine Interface (Intel MEI) Linux driver
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/irqreturn.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/pm_runtime.h>

#include "mei_dev.h"
#include "hw-me.h"
#include "hw-me-regs.h"

#include "mei-trace.h"

#define MEI_GSC_RPM_TIMEOUT 500

static int mei_gsc_read_hfs(const struct mei_device *dev, int where, u32 *val)
{
	struct mei_me_hw *hw = to_me_hw(dev);

	*val = ioread32(hw->mem_addr + where + 0xC00);

	return 0;
}

static int mei_gsc_probe(struct platform_device *platdev)
{
	struct mei_device *dev;
	struct mei_me_hw *hw;
	struct resource *bar;
	struct device *device;
	const struct platform_device_id *ent;
	const struct mei_cfg *cfg;
	int ret;

	ent = platform_get_device_id(platdev);
	cfg = mei_me_get_cfg(ent->driver_data);
	if (!cfg)
		return -ENODEV;

	device = &platdev->dev;

	dev = mei_me_dev_init(device, cfg);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto err;
	}

	bar = platform_get_resource(platdev, IORESOURCE_MEM, 0);

	hw = to_me_hw(dev);
	hw->mem_addr = devm_ioremap_resource(device, bar);
	if (IS_ERR(hw->mem_addr)) {
		dev_err(device, "mmio not mapped\n");
		ret = PTR_ERR(hw->mem_addr);
		goto err;
	}

	hw->irq = platform_get_irq(platdev, 0);
	if (hw->irq < 0) {
		ret = hw->irq;
		dev_err(device, "no irq for device %d\n", ret);
		goto err;
	}
	hw->read_fws = mei_gsc_read_hfs;

	platform_set_drvdata(platdev, dev);

	ret = devm_request_threaded_irq(device, hw->irq,
					mei_me_irq_quick_handler,
					mei_me_irq_thread_handler,
					IRQF_ONESHOT, KBUILD_MODNAME, dev);
	if (ret) {
		dev_err(device, "irq register failed %d\n", ret);
		goto err;
	}

	pm_runtime_get_noresume(device);
	pm_runtime_set_active(device);
	pm_runtime_enable(device);

	if (mei_start(dev)) {
		dev_err(device, "init hw failure.\n");
		ret = -ENODEV;
		goto err;
	}

	pm_runtime_set_autosuspend_delay(device, MEI_GSC_RPM_TIMEOUT);
	pm_runtime_use_autosuspend(device);

	ret = mei_register(dev, device);
	if (ret)
		goto register_err;

	dev_err(device, "probe completed succefully\n");
	return 0;

register_err:
	mei_stop(dev);

err:
	dev_err(device, "probe failed: %d\n", ret);
	platform_set_drvdata(platdev, NULL);
	return ret;
}

static int mei_gsc_remove(struct platform_device *platdev)
{
	struct mei_device *dev;

	dev = platform_get_drvdata(platdev);
	if (!dev)
		return -ENODEV;

	mei_stop(dev);

	mei_deregister(dev);

	pm_runtime_disable(&platdev->dev);

	return 0;
}

#ifdef CONFIG_PM
int mei_gsc_suspend(struct platform_device *platdev, pm_message_t state)
{
	struct mei_device *dev;
	struct device *device;

	device = &platdev->dev;
	dev_dbg(device, "suspend\n");

	dev = platform_get_drvdata(platdev);
	if (!dev)
		return -ENODEV;

	mei_stop(dev);

	mei_disable_interrupts(dev);

	return 0;
}

int mei_gsc_resume(struct platform_device *platdev)
{
	struct mei_device *dev;
	struct device *device;
	int err;

	device = &platdev->dev;
	dev_dbg(device, "resume\n");

	dev = platform_get_drvdata(platdev);
	if (!dev)
		return -ENODEV;

	err = mei_restart(dev);
	if (err)
		return err;

	/* Start timer if stopped in suspend */
	schedule_delayed_work(&dev->timer_work, HZ);

	return 0;
}
#else /* CONFIG_PM */
#define mei_gsc_suspend NULL
#define mei_gsc_resume NULL
#endif /* CONFIG_PM */

static const struct platform_device_id gsc_devtypes[] = {
	{
		.name = "mei-gsc",
		.driver_data = MEI_ME_GSC_CFG,
	},
	{
		.name = "mei-gscfi",
		.driver_data = MEI_ME_GSCFI_CFG,
	},
	{
		/* sentinel */
	}
};

static struct platform_driver mei_gsc_driver = {
	.driver = {
		.name = "mei-gsc",
		.owner = THIS_MODULE,
	},
	.probe	= mei_gsc_probe,
	.remove = mei_gsc_remove,
	.suspend = mei_gsc_suspend,
	.resume = mei_gsc_resume,
	.id_table = gsc_devtypes,
};

static int __init mei_gsc_init(void)
{
	int ret;

	ret = platform_driver_register(&mei_gsc_driver);

	return ret;
}
module_init(mei_gsc_init);

static void __exit mei_gsc_exit(void)
{
	platform_driver_unregister(&mei_gsc_driver);
}
module_exit(mei_gsc_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_ALIAS("platform:mei-gsc");
MODULE_LICENSE("GPL v2");
