/*
 * microvm device tree support
 *
 * This generates an device tree for microvm and exports it via fw_cfg
 * as "etc/fdt" to the firmware (edk2 specifically).
 *
 * The use case is to allow edk2 find the pcie ecam and the virtio
 * devices, without adding an ACPI parser, reusing the fdt parser
 * which is needed anyway for the arm platform.
 *
 * Note 1: The device tree is incomplete. CPUs and memory is missing
 *         for example, those can be detected using other fw_cfg files.
 *         Also pci ecam irq routing is not there, edk2 doesn't use
 *         interrupts.
 *
 * Note 2: This is for firmware only. OSes should use the more
 *         complete ACPI tables for hardware discovery.
 *
 * ----------------------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "system/device_tree.h"
#include "hw/char/serial-isa.h"
#include "hw/rtc/mc146818rtc.h"
#include "hw/sysbus.h"
#include "hw/virtio/virtio-mmio.h"
#include "hw/usb/xhci.h"
#include "qom/object.h"

#include "x86_dt_common.h"
#include <libfdt.h>


static bool debug;

static void dt_add_microvm_irq(MachineState *ms,
                               const char *nodename, uint32_t irq)
{
    int index = 0;

    if (irq >= IO_APIC_SECONDARY_IRQBASE) {
        irq -= IO_APIC_SECONDARY_IRQBASE;
        index++;
    }

    //qemu_fdt_setprop_cell(mms->fdt, nodename, "interrupt-parent",
    //                      mms->ioapic_phandle[index]);
    qemu_fdt_setprop_cells(ms->fdt, nodename, "interrupts", irq, 0);
}

static void dt_add_virtio(MachineState *ms, VirtIOMMIOProxy *mmio)
{
    SysBusDevice *dev = SYS_BUS_DEVICE(mmio);
    VirtioBusState *mmio_virtio_bus = &mmio->bus;
    BusState *mmio_bus = &mmio_virtio_bus->parent_obj;
    char *nodename;

    if (QTAILQ_EMPTY(&mmio_bus->children)) {
        return;
    }

    uint8_t plane = object_property_get_int(OBJECT(dev), "plane", &error_fatal);

    // Device is intended for guest usage
    if(plane == ms->device_plane)
        return;

    hwaddr base = dev->mmio[0].addr;
    hwaddr size = 512;
    //unsigned index = (base - VIRTIO_MMIO_BASE) / size;
    uint32_t irq = 0;//ms->virtio_irq_base + index;

    nodename = g_strdup_printf("/virtio_mmio@%" PRIx64, base);
    qemu_fdt_add_subnode(ms->fdt, nodename);
    qemu_fdt_setprop_string(ms->fdt, nodename, "compatible", "virtio,mmio");

    qemu_fdt_setprop_cell(ms->fdt, nodename, "plane", plane);

    qemu_fdt_setprop_sized_cells(ms->fdt, nodename, "reg", 2, base, 2, size);
    qemu_fdt_setprop(ms->fdt, nodename, "dma-coherent", NULL, 0);
    dt_add_microvm_irq(ms, nodename, irq);
    g_free(nodename);
}

static void dt_add_isa_serial(MachineState *ms, ISADevice *dev)
{
    const char compat[] = "ns16550";
    uint32_t irq = object_property_get_int(OBJECT(dev), "irq", &error_fatal);
    hwaddr base = object_property_get_int(OBJECT(dev), "iobase", &error_fatal);
    uint8_t plane = object_property_get_int(OBJECT(dev), "plane", &error_fatal);

    // Device is intended for guest usage
    if(plane == ms->device_plane)
        return;

    hwaddr size = 8;
    char *nodename;

    nodename = g_strdup_printf("/serial@%" PRIx64, base);
    qemu_fdt_add_subnode(ms->fdt, nodename);
    qemu_fdt_setprop(ms->fdt, nodename, "compatible", compat, sizeof(compat));
    qemu_fdt_setprop_sized_cells(ms->fdt, nodename, "reg", 2, base, 2, size);
    qemu_fdt_setprop_cell(ms->fdt, nodename, "plane", plane);

    dt_add_microvm_irq(ms, nodename, irq);

    //if (base == 0x3f8 /* com1 */) {
    //    qemu_fdt_setprop_string(ms->fdt, "/chosen", "stdout-path", nodename);
    //}

    g_free(nodename);
}

static void dt_setup_isa_bus(MachineState *ms, BusState *bus)
{
    BusChild *kid;
    Object *obj;

    QTAILQ_FOREACH(kid, &bus->children, sibling) {
        DeviceState *dev = kid->child;

        /* serial */
        obj = object_dynamic_cast(OBJECT(dev), TYPE_ISA_SERIAL);
        if (obj) {

            dt_add_isa_serial(ms, ISA_DEVICE(obj));
            continue;
        }

        if (debug) {
            fprintf(stderr, "%s: unhandled: %s\n", __func__,
                    object_get_typename(OBJECT(dev)));
        }
    }
}

struct TypeImpl
{
    const char *name;
};

static void dt_setup_sys_bus(MachineState *ms)
{
    BusState *bus;
    BusChild *kid;
    Object *obj;

    // PC Architecture always contains an ISA bus
    ISABus *isa_bus = (ISABus *)object_resolve_path_type("", TYPE_ISA_BUS, NULL);
    if(isa_bus) {
        fprintf(stderr,"device: %s\n",object_get_class(OBJECT(isa_bus))->type->name);

        BusState *bus_state = BUS(isa_bus);
        dt_setup_isa_bus(ms, bus_state);
    }

    bus = sysbus_get_default();

    QTAILQ_FOREACH(kid, &bus->children, sibling) {
        DeviceState *dev = kid->child;

        fprintf(stderr,"dev: %s type %s\n",dev->canonical_path, object_get_class(OBJECT(dev))->type->name);

        /* virtio */
        obj = object_dynamic_cast(OBJECT(dev), TYPE_VIRTIO_MMIO);
        if (obj) {
            dt_add_virtio(ms, VIRTIO_MMIO(obj));
            continue;
        }

        if (debug) {
            obj = object_dynamic_cast(OBJECT(dev), TYPE_IOAPIC);
            if (obj) {
                /* ioapic already added in first pass */
                continue;
            }
            fprintf(stderr, "%s: unhandled: %s\n", __func__,
                    object_get_typename(OBJECT(dev)));
        }
    }
}

void dt_setup_x86(MachineState *ms)
{
    int size = 0;

    ms->fdt = create_device_tree(&size);

    /* root node */
    qemu_fdt_setprop_string(ms->fdt, "/", "compatible", "svsm");
    qemu_fdt_setprop_cell(ms->fdt, "/", "#address-cells", 0x2);
    qemu_fdt_setprop_cell(ms->fdt, "/", "#size-cells", 0x2);
    qemu_fdt_setprop_cell(ms->fdt, "/", "device-plane", ms->device_plane);

    //qemu_fdt_add_subnode(ms->fdt, "/chosen");
    dt_setup_sys_bus(ms);

    fdt_pack(ms->fdt);

    /*if (g_file_set_contents("qemu.dtb", ms->fdt, size_fdt, NULL)) {
        fprintf(stderr,"dtb dumped to %s. Exiting.", "qemu.dtb");
        exit(0);
    } else {
        fprintf(stderr,"dtb dumped to %s. Exiting.", "qemu.dtb");
    }*/

}
