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

#include <sys/inotify.h>
#include <errno.h>
#include <poll.h>

#include <sys/types.h> 
#include <sys/socket.h> 

#include "hw/misc/bpf_injection_msg.h"

#include "hw/core/cpu.h"

//Affinity part
#include <sys/sysinfo.h>
#include <sched.h>
#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(64)

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

#define TYPE_NEWDEV_DEVICE "newdev"
#define NEWDEV(obj)        OBJECT_CHECK(NewdevState, obj, TYPE_NEWDEV_DEVICE)

#define NEWDEV_REG_PCI_BAR      0
#define NEWDEV_BUF_PCI_BAR      1
#define NEWDEV_REG_END          92
#define NEWDEV_REG_MASK         0xff
#define NEWDEV_BUF_MASK         0xffff
#define NEWDEV_BUF_SIZE         65536


//not used, misleading. OLD used only in ioregs R/W
#define NEWDEV_REG_STATUS_IRQ   0
#define NEWDEV_REG_CTRL         4
#define NEWDEV_REG_RAISE_IRQ    8
#define NEWDEV_REG_LOWER_IRQ    12

/* What's really used in this device!
*
* 0 for NEWDEV_REG_STATUS_IRQ [read] it's 0/sizeof(uint32_t)
* 0 for NEWDEV_REG_RAISE_IRQ [write] it's 0/sizeof(uint32_t)
* 1 for NEWDEV_REG_LOWER_IRQ [write] it's 4/sizeof(uint32_t)
*/

// DEVICE BUFMMIO STRUCTURE. OFFSET IN #bytes/sizeof(uint32_t)

// +---+--------------------------------+
// | 0 | irq_status [R] / raise_irq [W] |
// +---+--------------------------------+
// | 1 |          lower_irq [W]         |
// +---+--------------------------------+
// | 2 |      unspecified/reserved      |
// +---+--------------------------------+
// | 3 |      unspecified/reserved      |
// +---+--------------------------------+
// | 4 |                                |
// +---+                                |
// | 5 |            buffer              |
// +---+                                |
// |   |                                |
// |   |                                |
//                  ......
// |   |                                |
// |   |                                |
// +---+--------------------------------+


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


    bool hyperthreading_remapping; 
    
    int listen_fd;  //listening socket fd
    int connect_fd; //connected socket fd (use for command exchange)

} NewdevState;

static void newdev_raise_irq(NewdevState *newdev, uint32_t val);
static void connected_handle_read(void *opaque);
int map_hyperthread(cpu_set_t* set);


int map_hyperthread(cpu_set_t* set){
    //Modifies cpu_set only if one cpu is set in 
    int i=0;
    int setCount=0;
    int settedCpu;
    int remappedCpu = -1;
    for(i=0; i<MAX_CPU; i++){
        if(CPU_ISSET_S(i, SET_SIZE, set)){
            setCount++;
            settedCpu = i;
        }
    }
    if(setCount == 1){
        CPU_ZERO_S(SET_SIZE, set);
        if(settedCpu%2 == 0){
            remappedCpu = settedCpu / 2;
        }
        else{
            remappedCpu = (get_nprocs()/2) + (settedCpu / 2);
        }
        CPU_SET_S(remappedCpu, SET_SIZE, set);

        DBG("map_hyperthread [guest] %d -> %d [host]", settedCpu, remappedCpu);
    }
    else{
        DBG("map_hyperthread no if");
    }
    return remappedCpu;
}

static void accept_handle_read(void *opaque){
    NewdevState *newdev = opaque;

    DBG("accept_handle_read\n");
    DBG("incoming connection on socket fd:\t%d\n", newdev->listen_fd);
    

    /* CAN RAISE IRQ HERE */
    // DBG("raising irq for fun?\n");
    // newdev_raise_irq(newdev, 22);

    //Accept connection from peer
    newdev->connect_fd = accept(newdev->listen_fd, NULL, NULL);
    DBG("accepted connection from peer. connect_fd:\t%d\n", newdev->connect_fd);

    //Add connect_fd from list of watched fd in iothread select
    qemu_set_fd_handler(newdev->connect_fd, connected_handle_read, NULL, newdev);


    //Remove listen_fd from watched fd in iothread select
    qemu_set_fd_handler(newdev->listen_fd, NULL, NULL, NULL);

    //don't close listen_fd socket... useful for later reconnection ?
    //qemu_close(newdev->listen_fd);
    return;
}

static void connected_handle_read(void *opaque){
    NewdevState *newdev = opaque;
    // char buf[50];
    int len = 0;
    struct bpf_injection_msg_header* myheader;


    DBG("connect_handle_read\n");
    DBG("readable socket fd:\t%d\n", newdev->connect_fd);

    // Receive message header (version|type|payload_length) [place it in newdev->buf at offset 4*sizeof(uint32_t)]
    len = recv(newdev->connect_fd, newdev->buf + 4, sizeof(struct bpf_injection_msg_header), 0);
    if(len <= 0){
        DBG("len = %d [<=0] --> connection reset or error. Removing connect_fd, restoring listen_fd\n", len);
        //connection closed[0] or error[<0]

        //Remove connect_fd from watched fd in iothread select
        qemu_set_fd_handler(newdev->connect_fd, NULL, NULL, NULL);
        newdev->connect_fd = -1;

        //Add listen_fd from list of watched fd in iothread select
        qemu_set_fd_handler(newdev->listen_fd, accept_handle_read, NULL, newdev);  
        return;
    }
    myheader = (struct bpf_injection_msg_header*) newdev->buf + 4;
    print_bpf_injection_message(*myheader);   

    // Receive message payload. Place it in newdev->buf + 4*sizeof(uint32_t) + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t)
    // All those manipulation is because newdev->buf is a pointer to uint32_t so you have to provide offset in bytes/4 or in uint32_t
    len = recv(newdev->connect_fd, newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t), myheader->payload_len, 0);
    // DBG("payload received of len: %d bytes", len);

    //debug dump
    // {
    //     int payload_left = myheader->payload_len;
    //     int offset = 0;
    //     while(payload_left > 0){
    //         unsigned int tmp = *(unsigned int*)(newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t) + offset);
    //         DBG("value\t%x", tmp);
    //         offset += 1;
    //         payload_left -= 4;
    //         if(offset > 7)
    //             break;
    //     }
    // }

    //big switch depending on msg.header.type
    switch(myheader->type){
        case PROGRAM_INJECTION:
            // Program is stored in buf. Trigger interrupt to propagate this info
            // to the guest side. Convention::: use interrupt number equal to case
            DBG("PROGRAM_INJECTION-> interrupt fired");
            newdev_raise_irq(newdev, PROGRAM_INJECTION);
            {
                int i=0;
                CPUState* cpu = qemu_get_cpu(i);
                while(cpu != NULL){
                    DBG("cpu #%d[%d]\tthread id:%d", i, cpu->cpu_index, cpu->thread_id);
                    i++;
                    cpu = qemu_get_cpu(i);
                }
                DBG("Guest has %d vCPUS", i);
            }
            break;
        case PROGRAM_INJECTION_RESULT:
            break;
        case PROGRAM_INJECTION_AFFINITY:
            // Injection affinity infos are stored in buf.
            {
                struct cpu_affinity_infos_t* myaffinityinfo;
                int vCPU_count=0;
                CPUState* cpu = qemu_get_cpu(vCPU_count);
                while(cpu != NULL){
                    DBG("cpu #%d[%d]\tthread id:%d", vCPU_count, cpu->cpu_index, cpu->thread_id);
                    vCPU_count++;
                    cpu = qemu_get_cpu(vCPU_count);                
                }
                DBG("Guest has %d vCPUS", vCPU_count);
                myaffinityinfo = (struct cpu_affinity_infos_t*)(newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t));
                myaffinityinfo->n_vCPU = vCPU_count;
                DBG("#pCPU: %u", myaffinityinfo->n_pCPU);
                DBG("#vCPU: %u", myaffinityinfo->n_vCPU);
                newdev_raise_irq(newdev, PROGRAM_INJECTION_AFFINITY);
            }


            break;
        case PROGRAM_INJECTION_AFFINITY_RESULT:
            break;
        case SHUTDOWN_REQUEST:
            break;
        case ERROR:
            return;
        case RESET:
            {
                uint64_t value = 0xFFFFFFFF;                
                cpu_set_t *set;                
                CPUState* cpu;
                int vCPU_count=0;

                set = CPU_ALLOC(MAX_CPU);
                memcpy(set, &value, SET_SIZE);

                cpu = qemu_get_cpu(vCPU_count);
                while(cpu != NULL){
                    DBG("cpu #%d[%d]\tthread id:%d\t RESET affinity", vCPU_count, cpu->cpu_index, cpu->thread_id);
                    if (sched_setaffinity(cpu->thread_id, SET_SIZE, set) == -1){
                        DBG("error sched_setaffinity");
                    } 
                    vCPU_count += 1;
                    cpu = qemu_get_cpu(vCPU_count);   
                }  
                CPU_FREE(set);   
                break;
            }
        case PIN_ON_SAME:
            {                            
                cpu_set_t *set;                
                CPUState* cpu;
                int vCPU_count=0;
                set = CPU_ALLOC(MAX_CPU);
                CPU_SET_S(0, SET_SIZE, set);    //static pin on pCPU0

                cpu = qemu_get_cpu(vCPU_count);
                while(cpu != NULL){
                    DBG("cpu #%d[%d]\tthread id:%d\t PIN_ON_SAME [pcpu#%d]", vCPU_count, cpu->cpu_index, cpu->thread_id, 0);
                    if (sched_setaffinity(cpu->thread_id, SET_SIZE, set) == -1){
                        DBG("error sched_setaffinity");
                    } 
                    vCPU_count += 1;
                    cpu = qemu_get_cpu(vCPU_count);   
                }  
                CPU_FREE(set);   
                break;
            }
        case HT_REMAPPING:
            {                            
                newdev->hyperthreading_remapping = !newdev->hyperthreading_remapping;
                DBG("HT_REMAPPING: %d", newdev->hyperthreading_remapping);
            }
        default:
            //unexpected value is threated like an error 
            return;            
    }


    //old with raw data, now i use header+payload
    /*
        len = recv(newdev->connect_fd, buf, 4, 0);
    if(len <= 0){
        DBG("len = %d [<=0] --> connection reset or error. Removing connect_fd, restoring listen_fd\n", len);
        //connection closed[0] or error[<0]

        //Remove connect_fd from watched fd in iothread select
        qemu_set_fd_handler(newdev->connect_fd, NULL, NULL, NULL);
        newdev->connect_fd = -1;

        //Add listen_fd from list of watched fd in iothread select
        qemu_set_fd_handler(newdev->listen_fd, accept_handle_read, NULL, newdev);  
        return;
    }

    buf[4] = '\0';
    DBG("received %d characters. '%s'\n", len, buf);

    if(strcmp(buf, "init") == 0){
        DBG("INIT->");
        newdev_raise_irq(newdev, 22);
    }
    */

    return;
}


static void newdev_raise_irq(NewdevState *newdev, uint32_t val){
    newdev->irq_status |= val;
    DBG("raise irq\tirq_status=%x", newdev->irq_status);
    if (newdev->irq_status) {
        DBG("raise irq\tinside if");
        pci_set_irq(&newdev->pdev, 1);        
    }
}

static void newdev_lower_irq(NewdevState *newdev, uint32_t val){
    newdev->irq_status &= ~val;
    DBG("lower irq\tirq_status=%x", newdev->irq_status);
    if (!newdev->irq_status) {
        DBG("lower irq\tinside if");
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

static uint64_t newdev_bufmmio_read(void *opaque, hwaddr addr, unsigned size){
    NewdevState *newdev = opaque;
    unsigned int index;
    //if(system("cat ./shared/rare_string.txt; echo;") != 0){}

    addr = addr & NEWDEV_BUF_MASK;
    index = addr >> 2;

    if (addr + size > NEWDEV_BUF_SIZE * sizeof(uint32_t)) {
        DBG("Out of bounds BUF read, addr=0x%08"PRIx64, addr);
        return 0;
    }


    switch(index){
        case 0:
            DBG("BUF read [case 0] val=0x%08" PRIx32, newdev->irq_status);
            return newdev->irq_status;
        default:
            break;
    }
    // DBG("BUF read index=%u", index);
    // DBG("BUF read val=0x%08" PRIx32, newdev->buf[index]);
    return newdev->buf[index];
}

static void newdev_bufmmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    NewdevState *newdev = opaque;
    unsigned int index;


    addr = addr & NEWDEV_BUF_MASK;
    index = addr >> 2;

    if (addr + size > NEWDEV_BUF_SIZE * sizeof(uint32_t)) {
        DBG("Out of bounds BUF read, addr=0x%08"PRIx64, addr);
        return;
    }

    // DBG("BUF write val=0x%08" PRIx64, val);

    switch(index){
        case 0:
            newdev_raise_irq(newdev, val);
            break;
        case 1:        
            newdev_lower_irq(newdev, val);
            break;
        case 2:
            //doorbell region for guest->hw notification
            DBG("doorbell in device!");
            //process this response from guest daemon...

            //debug dump
            // {
            //     struct bpf_injection_msg_header* myheader;
            //     myheader = (struct bpf_injection_msg_header*) newdev->buf + 4;
            //     print_bpf_injection_message(*myheader); 
            //     int payload_left = myheader->payload_len;
            //     int offset = 0;
            //     while(payload_left > 0){
            //         unsigned int tmp = *(unsigned int*)(newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t) + offset);
            //         DBG("value\t%x", tmp);
            //         offset += 1;
            //         payload_left -= 4;
            //         if(offset > 7)
            //             break;
            //     }
            // }

            {
                struct bpf_injection_msg_header* myheader;
                myheader = (struct bpf_injection_msg_header*) newdev->buf + 4;
                send(newdev->connect_fd, myheader, sizeof(struct bpf_injection_msg_header), 0);
                send(newdev->connect_fd, newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t), myheader->payload_len, 0);
            }

            //reset doorbell
            newdev->buf[index] = 0;
            break;
        case 3:
            // {
            //     int vCPU_count=0;
            //     int i;
            //     int count_cpu = 0;
            //     int which_cpu = -1;
            //     int selected_cpu_thread_id = -1;
            //     uint64_t value = val;                
            //     cpu_set_t *set;                
            //     CPUState* cpu;

            //     set = CPU_ALLOC(MAX_CPU);
            //     memcpy(set, &value, SET_SIZE);
            //     for(i=0; i<MAX_CPU; i++){
            //         if(CPU_ISSET_S(i, SET_SIZE, set)){
            //             count_cpu++;
            //             which_cpu = i;
            //             printf("IN THE CPU_SET, cpu %d is set\n", i);
            //         }
            //     }

            //     cpu = qemu_get_cpu(vCPU_count);
            //     while(cpu != NULL){
            //         if(which_cpu == vCPU_count){
            //             selected_cpu_thread_id = cpu->thread_id;
            //         }
            //         DBG("cpu #%d[%d]\tthread id:%d", vCPU_count, cpu->cpu_index, cpu->thread_id);
            //         vCPU_count++;
            //         cpu = qemu_get_cpu(vCPU_count);                
            //     }
            //     DBG("Guest has %d vCPUS", vCPU_count);
            //     DBG("#pCPU: %u", get_nprocs()); //assuming NON hotpluggable cpus
            //     DBG("#vCPU: %u", vCPU_count);            

            //     DBG("---IOCTL_SCHED_SETAFFINITY triggered this.\nCall sched_setaffinity to bind vCPU%d(thread id %d) to pCPU%d", which_cpu, selected_cpu_thread_id, which_cpu);
            //     if(count_cpu == 1){
            //         if (sched_setaffinity(selected_cpu_thread_id, SET_SIZE, set) == -1){
            //             DBG("error sched_setaffinity");
            //         }                    
            //     }

            //     CPU_FREE(set);
            //     break;
            // }
            {
                int vCPU_count=0;
                uint64_t value = val;                
                cpu_set_t *set;                
                CPUState* cpu;

                set = CPU_ALLOC(MAX_CPU);
                memcpy(set, &value, SET_SIZE);                

                cpu = qemu_get_cpu(vCPU_count);
                while(cpu != NULL){
                    DBG("cpu #%d[%d]\tthread id:%d", vCPU_count, cpu->cpu_index, cpu->thread_id);
                    if(CPU_ISSET_S(vCPU_count, SET_SIZE, set)){
                        int remap = vCPU_count;
                        if(newdev->hyperthreading_remapping == true){                            
                            remap = map_hyperthread(set);   //if 1 cpu is set then remap, otherwise do nothing
                        }
                        if (sched_setaffinity(cpu->thread_id, SET_SIZE, set) == -1){
                            DBG("error sched_setaffinity");
                        }                          

                        DBG("---IOCTL_SCHED_SETAFFINITY triggered this.\nCall sched_setaffinity to bind vCPU%d(thread %d) to pCPU%d", vCPU_count, cpu->thread_id, remap);
                    }
                    vCPU_count++;
                    cpu = qemu_get_cpu(vCPU_count);                
                }                
                DBG("#pCPU: %u", get_nprocs()); //assuming NON hotpluggable cpus
                DBG("#vCPU: %u", vCPU_count);            

                CPU_FREE(set);
                break;
            }
        default:
            newdev->buf[index] = val;
            break;
    }


    return;
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

static const MemoryRegionOps newdev_bufmmio_ops = {
    .read = newdev_bufmmio_read,
    .write = newdev_bufmmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },

};

static int make_socket (uint16_t port){
  int sock;
  struct sockaddr_in name;

  /* Create the socket. */
  sock = socket (PF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror ("socket");
      return -1;
    }

  /* Give the socket a name. */
  name.sin_family = AF_INET;
  name.sin_port = htons (port);
  name.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (sock, (struct sockaddr *) &name, sizeof (name)) < 0)
    {
      perror ("bind");
      return -1;
    }

  return sock;
}

static void newdev_realize(PCIDevice *pdev, Error **errp)
{
    NewdevState *newdev = NEWDEV(pdev);
    uint8_t *pci_conf = pdev->config;

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

    /* Init memory mapped memory region, to expose eBPF programs. */
    memory_region_init_io(&newdev->mmio, OBJECT(newdev), &newdev_bufmmio_ops, newdev,
                    "newdev-buf", NEWDEV_BUF_SIZE * sizeof(uint32_t));
    pci_register_bar(pdev, NEWDEV_BUF_PCI_BAR, PCI_BASE_ADDRESS_SPACE_MEMORY, &newdev->mmio);

    newdev->buf = malloc(NEWDEV_BUF_SIZE * sizeof(uint32_t));

    /* Initialize device buffer */
    // s->buf = g_malloc0(BUF_LEN);
    

    //set_fd_handler?
    newdev->listen_fd = -1;
    newdev->connect_fd = -1;

    //setup ht (default=disabled)
    newdev->hyperthreading_remapping = false;

    newdev->listen_fd = make_socket(9999);
    if (newdev->listen_fd < 0){
        return;
    } 

    DBG("socket fd:\t%d", newdev->listen_fd);

    if (listen (newdev->listen_fd, 1) < 0){
      DBG("listen error\n");
      return;        
    }
    DBG("listen\n");

    qemu_set_fd_handler(newdev->listen_fd, accept_handle_read, NULL, newdev);        
    
    DBG("qemu listen_fd added");


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


    //unset_fd_handler
    if (newdev->listen_fd != -1) {
        qemu_set_fd_handler(newdev->listen_fd, NULL, NULL, NULL);
        qemu_close(newdev->listen_fd);
    }

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
