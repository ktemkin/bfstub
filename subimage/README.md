# Subimage Template

This subimage template can be used to generate a "subimage" payload for
Discharge, which allows Discharge to load Xen and Linux.

To create the subimage, place the following files into this folder:

* _xen_ -- The Xen hypervisor, compiled for AArch64.
* _xen.dtb_ -- The DTB to be used for Xen/Linux. Usually taken from your linux
  build tree.
* _Image_ -- The uncompressed AArch64 Linux kernel image to be used for dom0.


Next, use a device tree compiler to compile ```subimage.its``` into ```subimage.fit``:

```
    # With the device tree compiler:
    dtc -I dts -O dtb -p 1024 subimage.its > subimage.fit

    # With uboot-tools:
    mkimage -f subimage.its subimage.fit
```
