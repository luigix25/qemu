/*
 * QEMU educational PCI device
 *
 * Copyright (c) 2012-2015 Jiri Slaby
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qemu/module.h"
#include "qapi/visitor.h"

/* Debug information. Define it as 1 get for basic debugging,
 * and as 2 to get additional (verbose) memory listener logs. */
#define NEWDEV_DEBUG 1

#if NEWDEV_DEBUG > 0
#define DBG(fmt, ...) do { \
        fprintf(stderr, "newdev-pci: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

#define TYPE_NEWDEV_DEVICE "testnewdev"
#define NEWDEV(obj)        OBJECT_CHECK(NewdevState, obj, TYPE_NEWDEV_DEVICE)

#define NEWDEV_REG_PCI_BAR      0
#define NEWDEV_REG_END          92
#define NEWDEV_REG_MASK         0xff

#define NEWDEV_REG_CTRL         4
#define NEWDEV_REG_STATUS_IRQ   8
#define NEWDEV_REG_RAISE_IRQ    8
#define NEWDEV_REG_LOWER_IRQ    12



#define FACT_IRQ        0x00000001
#define DMA_IRQ         0x00000100

#define DMA_START       0x40000
#define DMA_SIZE        4096

#define BUF_LEN         500

static const char *regnames[] = {
    "STATUS",
    "CTRL",
    "RAISE_IRQ",
    "LOWER_IRQ",
    "NUM_RX_QUEUES",
    "NUM_TX_QUEUES",
    "NUM_RX_BUFS",
    "NUM_TX_BUFS",
    "RX_CTX_SIZE",
    "TX_CTX_SIZE",
    "DOORBELL_SIZE",
    "QUEUE_SELECT",
    "CTX_PADDR_LO",
    "CTX_PADDR_HI",
    "PROG_SELECT",
    "PROG_SIZE",
    "DOORBELL_GVA_LO",
    "DOORBELL_GVA_HI",
    "VERSION",
    "FEATURES",
    "DUMP_LEN",
    "DUMP_INPUT",
    "DUMP_OFS",
};


typedef struct {
    PCIDevice pdev;
    MemoryRegion regs;
    MemoryRegion mmio;

    /* Storage for the I/O registers. */
    uint32_t ioregs[NEWDEV_REG_END >> 2];

    /* Storage for the buffer. */
    uint32_t *buf;

    QemuThread thread;
    QemuMutex thr_mutex;
    QemuCond thr_cond;
    bool stopping;

    uint32_t irq_status;

} NewdevState;

static bool newdev_msi_enabled(NewdevState *newdev)
{
    return msi_enabled(&newdev->pdev);
}

static void newdev_raise_irq(NewdevState *newdev, uint32_t val)
{
    newdev->irq_status |= val;
    if (newdev->irq_status) {
        if (newdev_msi_enabled(newdev)) {
            msi_notify(&newdev->pdev, 0);
        } else {
            pci_set_irq(&newdev->pdev, 1);
        }
    }
}

static void newdev_lower_irq(NewdevState *newdev, uint32_t val)
{
    newdev->irq_status &= ~val;

    if (!newdev->irq_status && !newdev_msi_enabled(newdev)) {
        pci_set_irq(&newdev->pdev, 0);
    }
}

static uint64_t newdev_io_read(void *opaque, hwaddr addr, unsigned size){
    NewdevState *newdev = opaque;
    uint64_t val;
    unsigned int index;

    addr = addr & NEWDEV_REG_MASK;
    index = addr >> 2;

    if (addr >= NEWDEV_REG_END) {
        DBG("Unknown I/O read, addr=0x%08"PRIx64, addr);
        return 0;
    }

    // assert(index < ARRAY_SIZE(regnames));

    switch(addr){
        case NEWDEV_REG_STATUS_IRQ:
            val = newdev->irq_status;
            break;
        default:
            val = newdev->ioregs[index];
            break;            
    }

    DBG("I/O read from %s, val=0x%08" PRIx64, regnames[index], val);

    return val;
}

static void newdev_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    NewdevState *newdev = opaque;
    unsigned int index;

    addr = addr & NEWDEV_REG_MASK;
    index = addr >> 2;

    if (addr >= NEWDEV_REG_END) {
        DBG("Unknown I/O write, addr=0x%08"PRIx64", val=0x%08"PRIx64,
            addr, val);
        return;
    }

    assert(index < ARRAY_SIZE(regnames));

    DBG("I/O write to %s, val=0x%08" PRIx64, regnames[index], val);

    switch(addr){
        case NEWDEV_REG_RAISE_IRQ:
            newdev_raise_irq(newdev, val);
        case NEWDEV_REG_LOWER_IRQ:
            newdev_lower_irq(newdev, val);
            break;
        default:            
            newdev->ioregs[index] = val;
            break;
    }

}


static const MemoryRegionOps newdev_io_ops = {
    .read = newdev_io_read,
    .write = newdev_io_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },

};


static void newdev_realize(PCIDevice *pdev, Error **errp)
{
    NewdevState *newdev = NEWDEV(pdev);
    uint8_t *pci_conf = pdev->config;

    DBG("**** starting realize... ****");
    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    //timer_init_ms(&newdev->dma_timer, QEMU_CLOCK_VIRTUAL, newdev_dma_timer, newdev);

    qemu_mutex_init(&newdev->thr_mutex);
    qemu_cond_init(&newdev->thr_cond);

    /* Init I/O mapped memory region, exposing newdev registers. */
    memory_region_init_io(&newdev->regs, OBJECT(newdev), &newdev_io_ops, newdev,
                    "newdev-regs", NEWDEV_REG_MASK + 1);
    pci_register_bar(pdev, NEWDEV_REG_PCI_BAR, PCI_BASE_ADDRESS_SPACE_MEMORY, &newdev->regs);


    // newdev->buf = malloc(NEWDEV_BUF_SIZE * sizeof(uint32_t));

    /* Initialize device buffer */
    // s->buf = g_malloc0(BUF_LEN);

    DBG("**** device realized ****");
}

static void newdev_uninit(PCIDevice *pdev)
{
    NewdevState *newdev = NEWDEV(pdev);

    qemu_mutex_lock(&newdev->thr_mutex);
    newdev->stopping = true;
    qemu_mutex_unlock(&newdev->thr_mutex);
    qemu_cond_signal(&newdev->thr_cond);
    qemu_thread_join(&newdev->thread);

    qemu_cond_destroy(&newdev->thr_cond);
    qemu_mutex_destroy(&newdev->thr_mutex);

    // timer_del(&newdev->dma_timer);
    msi_uninit(pdev);

    DBG("**** device unrealized ****");
}


static void newdev_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = newdev_realize;
    k->exit = newdev_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x11ea;
    // k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    // k->vmsd = &vmstate_newdev;
    // k->props = newdev_properties;
}

static void newdev_instance_init(Object *obj)
{
    
    //NewdevState *edu = NEWDEV(obj);

    // edu->dma_mask = (1UL << 28) - 1;
    // object_property_add_uint64_ptr(obj, "dma_mask",
    //                                &edu->dma_mask, OBJ_PROP_FLAG_READWRITE,
    //                                NULL);
}

static void newdev_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo newdev_info = {
        .name          = TYPE_NEWDEV_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(NewdevState),
        .instance_init = newdev_instance_init,
        .class_init    = newdev_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&newdev_info);
}
type_init(newdev_register_types)
