# Building the kernel for the Intel(R) Iris(R) Xe MAX Graphics

The latest kernel driver for the Intel Iris Xe MAX graphics adapter is
available in source form in the
[intel-gpu/kernel](https://github.com/intel-gpu/kernel) project on GitHub.

This guide provides instructions for downloading, building, and
installing the kernel source as well as required firmware files. The
instructions are written for Ubuntu 20.04, and should be adaptable to
other operating systems to build a Linux* kernel using the sources
published.

> **NOTE**: The kernel you build while following the instructions on
> this page is not recommended for use as the primary kernel in systems
> configured with both an Intel Iris Xe graphics adapter and an Intel
> Iris Xe MAX graphics adapter. On those systems, we recommend you
> follow the instructions provided on [this guide](https://dgpu-docs.intel.com/devices/iris-xe-max-graphics/index.html), which
> uses a different kernel for each of the two adapters. If you try and
> boot the kernel built on this page directly on a system with the Intel
> Iris Xe graphics adapter, the system may lock up during boot.

## Configure the host

Install packages necessary for building the Linux kernel from source:

```bash
sudo apt install build-essential git gcc bison flex libssl-dev bc cpio \
  openssl lz4
```
For openSUSE Linux, below the packages necessary

```bash
sudo zypper install patterns-devel-C-C++-devel_C_C++  patterns-devel-base-devel_kernel \
  git bison flex libopenssl-devej bc cpio  openssl lz4
```

## Download the kernel source and build it

The following will download the kernel sources from
[GitHub](https://github.com/intel-gpu/kernel), configure it, and compile
it in the ${HOME}/kernel-xe-max directory.

```bash
cd ${HOME}
git clone --branch=main --depth=1 \
  https://github.com/intel-gpu/kernel \
  kernel-xe-max
cd kernel-xe-max
cp /boot/config-$(uname -r) .config
make olddefconfig
make -j $(nproc --all) targz-pkg LOCALVERSION="-xe-max"
```

At the end of the build, a tarball will be ready in ${HOME}/kernel-xe-max:

```bash
ls -l ${HOME}/kernel-xe-max/*.gz
```

## Install the Xe MAX firmware

Prior to installing the custom kernel, you need to install the firmware
files required by the Intel Iris Xe MAX graphics adapter. The following
will download an archive of the latest firmware files and decompress
them into /lib/firmware/i915, where the kernel will look for them while
booting:

```bash
wget -qO - \
  https://repositories.intel.com/graphics/firmware/linux-firmware-dg1_2020.43.tgz |
  sudo tar -C /lib/firmware/i915 -xvz --warning=no-timestamp
```

## Install the kernel supporting Intel Iris Xe MAX graphics

You can now install the custom kernel. This is done after the firmware
files are installed to make sure that the firmware files are available
while the initial ramdisk is created during the kernel installation:

```bash
mkdir kernel-xe-max-install
tar -C kernel-xe-max-install -xzf linux-5.4.48-xe-max-x86.tar.gz
sudo cp -r kernel-xe-max-install/lib/modules/5.4.48-xe-max /lib/modules/
sudo /sbin/installkernel \
  5.4.48-xe-max \
  kernel-xe-max-install/boot/vmlinuz-5.4.48-xe-max \
  kernel-xe-max-install/boot/System.map-5.4.48-xe-max \
  /boot
```

Once the kernel has been installed, you can reboot:

```bash
sudo reboot
```

## Verify the Intel Iris Xe MAX graphics driver is initialized

Use *lspci* to verify the Intel Iris Xe MAX graphics driver is initialized
by the i915 kernel driver:

```bash
lspci -nnk | grep VGA -A 3 | grep -E "VGA|driver"
```

Output should look similar to the following:

```bash
00:03.0 VGA compatible controller [0300]: Intel Corporation Device [8086:4905] (rev 01)
        Kernel driver in use: i915
```

## Install user space media and compute packages

You now have a kernel with support for the Intel Iris Xe MAX graphics adapter,
and can install the latest compute and media packages, as documented in the
[installation guides](https://dgpu-docs.intel.com/installation-guides/ubuntu/ubuntu-focal.html).

### Configure permissions to access GPU

In order to access GPU capabilities, a user needs to have the correct
permissions on the system. The follwing will add the user to the render
group owning /dev/dri/render*:

```bash
sudo gpasswd -a ${USER} render
newgrp render
```

## Tests

### Verify the kernel is the version you built

This should report 'Linux 5.4.48-xe-max':

```bash
uname -sr
```

### Verify the graphics platform name

Verify 'platform: DG1' is listed in i915_capabilities:

```bash
sudo grep "platform:" /sys/kernel/debug/dri/0/i915_capabilities
```

### Verify Open CL

After you have followed the installation guides to install the user space packages,
you can verify that OpenCL driver is working by using clinfo:

```bash
sudo apt install clinfo
clinfo
```

### Verify media

After you have followed the installation guides to install the user space packages,
you can verify that the media driver is working by using vainfo:


```bash
sudo apt install vainfo
vainfo
```

Copyright 2020 by Intel Corporation. All rights reserved.
