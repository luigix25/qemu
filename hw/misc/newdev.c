/*
 * QEMU extensible paravirtualization device
 * 2020 Giacomo Pellicci
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
#include "qemu/module.h"
#include "qemu/sockets.h"
#include "qapi/visitor.h"
#include "qapi/error.h"

#include <errno.h>

#include "hw/misc/bpf_injection_msg.h"
#include "hw/core/cpu.h"

#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qstring.h"

/* qom-get and qom-set */
/* This #include leads to recompilation of over 300 files each time. For now using forward declaration */
//#include "qapi/qapi-commands-qom.h"
void qmp_qom_set(const char *path, const char *property, QObject *value, Error **errp);
QObject *qmp_qom_get(const char *path, const char *property, Error **errp);

//Affinity part
#include <sys/sysinfo.h>

#define MAX_CPU 64
#define SET_SIZE CPU_ALLOC_SIZE(MAX_CPU)
#define NEWDEV_DEVICE_ID 0x11ea

/* Debug information. Define it as 1 get for basic debugging,
 * and as 2 to get additional (verbose) memory listener logs. */
#define NEWDEV_DEBUG 1

#if NEWDEV_DEBUG > 0
#define DBG(fmt, ...) do { \
        fprintf(stderr, "newdev-pci: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) 
#endif

#define TYPE_NEWDEV_DEVICE "newdev"
#define NEWDEV(obj)        OBJECT_CHECK(NewdevState, obj, TYPE_NEWDEV_DEVICE)

#define NEWDEV_BUF_PCI_BAR       1

/* Represents the number of rows */
#define NEWDEV_REG_SIZE                 8
#define NEWDEV_BUF_SIZE                 65536
#define NEWDEV_WRITE_BUF_SIZE           512

//#define NEWDEV_ADDRESSABLE_MASK         0x1ffff
#define NEWDEV_ADDRESSABLE_SIZE         NEWDEV_REG_SIZE + NEWDEV_BUF_SIZE + NEWDEV_WRITE_BUF_SIZE -1
#define NEWDEV_PCI_BAR_SIZE             1048576  /* 2^20; Must be a power of two! */

#define NEWDEV_REGISTER_BOUNDARY        NEWDEV_REG_SIZE
#define NEWDEV_BUF_BOUNDARY             NEWDEV_BUF_SIZE + NEWDEV_REG_SIZE

#define VCPU_PINNING_TYPE               1
#define DYNAMIC_MEM_TYPE                2
#define FIREWALL_TYPE                   3


/* Data in Doorbell */
#define NEWDEV_DOORBELL_RESULT_READY        1
#define NEWDEV_DOORBELL_INJECTION_FINISHED  2

#define VIRTIO_MEM_ID "/machine/peripheral/vm0"

#define MEGA (1024*1024)
#define GIGA (1024*MEGA)

#define backoff_time 100

// DEVICE BUFMMIO STRUCTURE. OFFSET IN #bytes/sizeof(uint32_t)

// +---+--------------------------------+
// | 0 | irq_status [R] / raise_irq [W] |
// +---+--------------------------------+
// | 1 |          lower_irq [W]         |
// +---+--------------------------------+
// | 2 |        doorbell region         |
// +---+--------------------------------+
// | 3 |      unspecified/reserved      |
// +---+--------------------------------+
// | 4 |      unspecified/reserved      |
// +---+--------------------------------+
// | 5 |      unspecified/reserved      |
// +---+--------------------------------+
// | 6 |      unspecified/reserved      |
// +---+--------------------------------+
// | 7 |      unspecified/reserved      |
// +---+--------------------------------+
// | 8 |                                | /* Buffer used by the user to read */
// +---+                                |
// | 9 |            buffer              |
// +---+                                |
//
//                  ......
// +---------+                          +
// | 64K + 7 |                          |   /* 65543 */
// +---------+--------------------------+
// | 64K + 8 |      Write Buffer        |   /* 65544 */
// +---------+                          |   /* 512B Buffer that is used by the user to write */
//                  ......
// +---------+                          +
// |64K + 135|                          |   /* 65671 */
// +---------+--------------------------+

typedef struct {
    PCIDevice pdev;
    MemoryRegion mmio;

    /* Registers */
    uint32_t registers[NEWDEV_REG_SIZE];

    /* Storage for the buffer. */
    uint32_t *buf;
    uint32_t *write_buf;

    uint32_t irq_status;
    bool user_reading;  //Is true when the IRQ is fired, false when user tells the device that the read operation is complete

    uint32_t vCPU_counter[MAX_CPU];

    bool hyperthreading_remapping; 
    
    int listen_fd;  //listening socket fd
    int connect_fd; //connected socket fd (use for command exchange)

    //For Dynamic Memory
    uint64_t last_timeslot;
    uint64_t global_counter;
    uint64_t no_reset_counter;
    uint64_t timeslot_duration;

    uint64_t requested_ram;
    uint64_t max_ram;

    QEMUTimer timer;

} NewdevState;

static void newdev_raise_irq(NewdevState *newdev, uint32_t val);
static void connected_handle_read(void *opaque);
int map_hyperthread(cpu_set_t* set);
bool increase_ram(NewdevState *newdev);
bool decrease_ram(NewdevState *newdev);
bool send_ram_request(uint64_t requested_size);

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

        // DBG("map_hyperthread [guest] %d -> %d [host]", settedCpu, remappedCpu);
    }
    return remappedCpu;
}

static void accept_handle_read(void *opaque){
    NewdevState *newdev = opaque;

    DBG("accept_handle_read\n");
    DBG("incoming connection on socket fd:\t%d\n", newdev->listen_fd);
    
    //Accept connection from peer
    newdev->connect_fd = qemu_accept(newdev->listen_fd, NULL, NULL);
    DBG("accepted connection from peer. connect_fd:\t%d\n", newdev->connect_fd);

    if(newdev->user_reading){ 
        DBG("Ignoring connection: busy!");
        qemu_close(newdev->connect_fd);
        newdev->connect_fd = -1;
        return;
    }

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
    int len = 0;
    struct bpf_injection_msg_header* myheader;

    DBG("connect_handle_read\n");
    DBG("readable socket fd:\t%d\n", newdev->connect_fd);

    // Receive message header (version|type|payload_length) [place it in newdev->buf at offset 4*sizeof(uint32_t)]
    len = recv(newdev->connect_fd, newdev->buf, sizeof(struct bpf_injection_msg_header), 0);
    if(len <= 0){
        //connection closed[0] or error[<0]
        DBG("len = %d [<=0] --> connection reset or error.\n", len);
        goto close_and_listen;
    }
    myheader = (struct bpf_injection_msg_header*) newdev->buf;
    print_bpf_injection_message(*myheader);   

    // Receive message payload. Place it in newdev->buf + 4 + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t)
    // All those manipulation is because newdev->buf is a pointer to uint32_t so you have to provide offset in bytes/4 or in uint32_t
    len = recv(newdev->connect_fd, newdev->buf + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t), myheader->payload_len, 0);
    DBG("Received all Data, closing connection\n");

    //big switch depending on msg.header.type
    switch(myheader->type){
        case PROGRAM_INJECTION:
            // Program is stored in buf. Trigger interrupt to propagate this info
            // to the guest side. Convention::: use interrupt number equal to case
            DBG("PROGRAM_INJECTION-> interrupt fired");
            newdev->user_reading = true;
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
                myaffinityinfo = (struct cpu_affinity_infos_t*)(newdev->buf + sizeof(struct bpf_injection_msg_header)/sizeof(uint32_t));
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

    close_and_listen:

    DBG("Closing Connecton\n");
    //Close Socket
    qemu_close(newdev->connect_fd);
    //Remove connect_fd from watched fd in iothread select
    qemu_set_fd_handler(newdev->connect_fd, NULL, NULL, NULL);
    newdev->connect_fd = -1;
    //Add listen to the iothread select
    qemu_set_fd_handler(newdev->listen_fd, accept_handle_read, NULL, newdev);  
    return;
}

static void newdev_raise_irq(NewdevState *newdev, uint32_t val){
    newdev->irq_status |= val;
    //DBG("raise irq\tirq_status=%x", newdev->irq_status);
    if (newdev->irq_status) {
        //DBG("raise irq\tinside if");
        pci_set_irq(&newdev->pdev, 1);        
    }
}

static void newdev_lower_irq(NewdevState *newdev, uint32_t val){
    newdev->irq_status &= ~val;
    //DBG("lower irq\tirq_status=%x", newdev->irq_status);
    if (!newdev->irq_status) {
        //DBG("lower irq\tinside if");
        pci_set_irq(&newdev->pdev, 0);
    }
}

static void vcpu_pinning(NewdevState *newdev, uint64_t* ptr, uint32_t size){

    uint64_t cpu_mask  = *(ptr);
    uint64_t operation = *(ptr+1);

    DBG("size: %d\n",size);
    DBG("CPU_MASK %lu\n",cpu_mask);

    uint32_t index = __builtin_ctzll(cpu_mask);
    CPUState *cpu = qemu_get_cpu(index);
    cpu_set_t *cpu_set = CPU_ALLOC(MAX_CPU);

    if(cpu_set == NULL){
        DBG("Error while allocating SET\n");
        goto exit;
    }

    DBG("vCPU: %d\n",index);

    CPU_ZERO_S(SET_SIZE,cpu_set);

    if(cpu == NULL){
        DBG("vCPU NOT FOUND!!!\n");
        goto exit;
    }
    
    /*if(newdev->hyperthreading_remapping == true){
        remap = map_hyperthread(set);   //if 1 cpu is set then remap, otherwise do nothing
    } */

    if(operation){
        DBG("UNPIN\n");
        newdev->vCPU_counter[index]--;
        if(newdev->vCPU_counter[index] == 0){
            uint64_t all = (uint64_t)-1;
            memcpy(cpu_set,&all,sizeof(uint64_t));
        
            if(sched_setaffinity(cpu->thread_id, SET_SIZE, cpu_set) == -1){
                perror("sched_setaffinity");
            }
            DBG("Unpinned PID: %d\n",cpu->thread_id); 
        }


    } else {
        DBG("PIN\n");
        if(__builtin_popcountll(cpu_mask) > 1){
            DBG("Pinning to more than 1 CPU: not implemented!\n");
            goto exit;
        }

        newdev->vCPU_counter[index]++;
        if(newdev->vCPU_counter[index] == 1){
            CPU_SET_S(index,SET_SIZE, cpu_set);
            if(sched_setaffinity(cpu->thread_id, SET_SIZE, cpu_set) == -1){
                perror("sched_setaffinity");
            }
            DBG("Pinned PID: %d\n",cpu->thread_id);
        }

    }

    exit:

    CPU_FREE(cpu_set);


}

bool send_ram_request(uint64_t requested_size){
    QNum *number = qnum_from_uint(requested_size);
    const char *qom_path = VIRTIO_MEM_ID;
    Error *err = NULL;

    qmp_qom_set(qom_path, "requested-size", (QObject *)number, &err);
    if(err != NULL){
        DBG("Error requesting ram change!");
        return false;
    }
    
    return true;

}

bool decrease_ram(NewdevState *newdev){
    uint64_t ram_step = 64 * MEGA;

    //Someone can modify requested-size from outside
    Error *err = NULL;
    QNum *qnum = (QNum*) qmp_qom_get(VIRTIO_MEM_ID,"requested-size",&err);
    uint64_t current_requested_ram = qnum_get_uint(qnum);
    newdev->requested_ram = current_requested_ram;

    if(newdev->requested_ram == 0){
        DBG("no more ram to deallocate!");
        return false;
    }

    if(newdev->requested_ram < ram_step){
        newdev->requested_ram = 0;
    } else {
        newdev->requested_ram -= ram_step;
    }

    DBG("[DECREASE] Requesting RAM %luM",(newdev->requested_ram/MEGA));
    return send_ram_request(newdev->requested_ram);
}

bool increase_ram(NewdevState *newdev){

    uint64_t ram_step = 256 * MEGA;

    //Someone can modify requested-size from outside
    Error *err = NULL;
    QNum *qnum = (QNum*) qmp_qom_get(VIRTIO_MEM_ID,"requested-size",&err);
    uint64_t current_requested_ram = qnum_get_uint(qnum);
    newdev->requested_ram = current_requested_ram;

    if(newdev->requested_ram == newdev->max_ram){
        DBG("no more ram to allocate!");
        return false;
    }

    if(newdev->requested_ram + ram_step <= newdev->max_ram){
        newdev->requested_ram += ram_step;
    } else if(newdev->requested_ram + ram_step > newdev->max_ram){
        newdev->requested_ram = newdev->max_ram;
    }

    DBG("[INCREASE] Requesting RAM %luM",(newdev->requested_ram/MEGA));
    return send_ram_request(newdev->requested_ram);

}

static void dynamic_memory(NewdevState *newdev, void* ptr, uint32_t size){

    typedef struct {
        uint64_t timeslot_start;
        uint64_t timeslot_duration;
        uint64_t global_threshold;
        uint64_t cpu;
        uint64_t counter;
    } counter_t;

    counter_t *counter = (counter_t *)ptr;

    newdev->timeslot_duration = counter->timeslot_duration;

    DBG("%lu %lu %lu\n",counter->timeslot_duration,counter->cpu,counter->counter);

    if(newdev->last_timeslot == 0){ //first message
        newdev->last_timeslot = counter->timeslot_start;
        newdev->global_counter = counter->counter;
    } else if(newdev->last_timeslot <= counter->timeslot_start || newdev->last_timeslot < counter->timeslot_start - counter->timeslot_duration){
        //Same start, or unaligned start; ex: last_time_slot 100, receviced 150 with slot duration 100
        newdev->global_counter += counter->counter;
    } else { /* Too long since last swap; Did not go over the threshold */
        newdev->global_counter = counter->counter;
        newdev->last_timeslot = counter->timeslot_start;
        newdev->no_reset_counter = 0;
    }

    DBG("-----------------");
    //DBG("timeslot_start : %lu",counter->timeslot_start);
    //DBG("cpu            : %lu",counter->cpu);
    DBG("global counter : %lu",newdev->global_counter);
    DBG("no_rst counter : %lu",newdev->no_reset_counter);
    DBG("-----------------\n");

    if(newdev->global_counter > counter->global_threshold){
        newdev->no_reset_counter += newdev->global_counter;
        newdev->last_timeslot = 0;
        newdev->global_counter = 0;
        increase_ram(newdev);
    }

    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    //If for 100 time slots no local threshold is triggered, ram is reduced
    timer_mod(&newdev->timer,now+backoff_time*counter->timeslot_duration);

}

static void firewall_op(NewdevState *newdev, void* ptr, uint32_t size){

    enum rule {DROP, ACCEPT, UNKNOWN = -1};

    #define MAX_STRLEN 20

    typedef struct{
        const char table_name[MAX_STRLEN];
        const char chain_name[MAX_STRLEN];
        uint32_t ip;
        uint32_t rule;
    } firewall_info_t;

    firewall_info_t *rule = (firewall_info_t *)ptr;

    const char *accept = "ACCEPT";
    const char *drop = "DROP";

    const char *rule_ptr;

    if(rule->rule == DROP)
        rule_ptr = drop;
    else if(rule->rule == ACCEPT)
        rule_ptr = accept;

    uint8_t *ip_ptr = (uint8_t*) &rule->ip;

    //destination address is hardcoded, chain is forced to FORWARD

    char rule_buffer[200];
    sprintf(rule_buffer,"iptables -t %s -A FORWARD -s %d.%d.%d.%d -j %s -d 192.168.3.4",rule->table_name,ip_ptr[0],ip_ptr[1],ip_ptr[2],ip_ptr[3],rule_ptr);

    DBG("RULE: %s\n",rule_buffer);
    //DBG("iptables -t %s -A %s -s %d.%d.%d.%d -j %s -d 192.168.3.4",rule->table_name,rule->chain_name,ip_ptr[0],ip_ptr[1],ip_ptr[2],ip_ptr[3],rule_ptr);

    //DBG("IP: %x RULE: %d table: %s chain: %s",rule->ip,rule->rule,rule->table_name,rule->chain_name);



    if(system(rule_buffer) < 0)
        return;
}


// 64 bits
/* +-----------------------------+*/
/* |            Type             |*/  //vCPU Pinning and so on
/* +-----------------------------+*/
/* |        Payload Size         |*/
/* +-----------------------------+*/
/* |           Payload           |*/
/* +-----------------------------+*/

static void handle_doorbell(NewdevState *newdev, uint32_t value){

    switch (value){
        case NEWDEV_DOORBELL_RESULT_READY:{
            //Data are passed as an array of 64 bits
            uint64_t *ptr = (uint64_t*)(newdev->write_buf);
            uint64_t type = *ptr;
            uint64_t size = *(ptr+1);

            if(type == VCPU_PINNING_TYPE)
                vcpu_pinning(newdev,ptr+2,size);
            else if(type == DYNAMIC_MEM_TYPE)
                dynamic_memory(newdev,ptr+2,size);
            else if(type == FIREWALL_TYPE){
                firewall_op(newdev,ptr+2,size);
            }

            //Signaling that processing of the data was completed
            return newdev_raise_irq(newdev,PROGRAM_INJECTION_RESULT);
        }
        case NEWDEV_DOORBELL_INJECTION_FINISHED:
            newdev->user_reading = false;
            return;
        default:
            DBG("Unrecognized Value in Doorbell!\n");
            return;
    }

    DBG("Unrecognized Type of Injection!\n");


}

static void write_registers(NewdevState *newdev, uint32_t index, uint32_t val){
    
    switch(index){
        case 0:
            newdev_raise_irq(newdev, val);  //TODO: FIX
            break;
        case 1:
            newdev_lower_irq(newdev, val);  //ACK the IRQ
            break;
        case 2:
            //doorbell region: write of the results completed
            //DBG("doorbell in device!");
            handle_doorbell(newdev,val);
            break;
        default:
            newdev->registers[index] = val;
            break;
    }
}

static uint32_t read_registers(NewdevState *newdev, uint32_t index){

    switch(index){
        case 0:
            //DBG("BUF read [case 0] val=0x%08" PRIx32, newdev->irq_status);
            return newdev->irq_status;
        default:
            return newdev->registers[index];
    }

}

static uint64_t newdev_bufmmio_read(void *opaque, hwaddr addr, unsigned size){
    NewdevState *newdev = opaque;
    unsigned int index;

    index = addr/sizeof(uint32_t);

    if (addr + size > NEWDEV_ADDRESSABLE_SIZE) {
        DBG("Out of bounds BUF read, addr=0x%08"PRIx64, addr);
        return 0;
    }

    /* Read from registers */
    if(index < NEWDEV_REGISTER_BOUNDARY){
        return read_registers(newdev,index);
    } else if(index < NEWDEV_BUF_BOUNDARY){
        index -= NEWDEV_REGISTER_BOUNDARY;
        return newdev->buf[index];
    } 

    index -= NEWDEV_BUF_BOUNDARY;
    return newdev->write_buf[index];

    // DBG("BUF read index=%u", index);
    // DBG("BUF read val=0x%08" PRIx32, newdev->buf[index]);
}

static void newdev_bufmmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size){
    NewdevState *newdev = opaque;
    uint32_t index;

    index = addr/sizeof(uint32_t);

    if (index + size > NEWDEV_ADDRESSABLE_SIZE) {
        DBG("Out of bounds BUF write, addr=0x%08"PRIx64, addr);
        DBG("bounds addr=0x%08"PRIx64,(long unsigned int) NEWDEV_ADDRESSABLE_SIZE);
        return;
    }

    //Writing into registers
    if(index < NEWDEV_REGISTER_BOUNDARY){
        return write_registers(newdev,index,val);
    } else if(index < NEWDEV_BUF_BOUNDARY){
        DBG("should not write here! %d\n",index);

        index -= NEWDEV_REGISTER_BOUNDARY;
        newdev->buf[index] = val;
        return;
    }

    index -= NEWDEV_BUF_BOUNDARY;
    newdev->write_buf[index] = val;

}


static const MemoryRegionOps newdev_bufmmio_ops = {
    .read = newdev_bufmmio_read,
    .write = newdev_bufmmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },

};

static int make_socket(uint16_t port){
  int sock;
  struct sockaddr_in name;

  /* Create the socket. */
  sock = qemu_socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror ("socket");
      return -1;
    }

  /* Give the socket a name. */
  name.sin_family = AF_INET;
  name.sin_port = htons(port);
  name.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind (sock, (struct sockaddr *) &name, sizeof (name)) < 0)
    {
      perror ("bind");
      return -1;
    }

  return sock;
}

static void timer_callback(void *opaque){

    NewdevState *newdev = (NewdevState*)opaque;
    if(decrease_ram(newdev) == false) //no more ram to deallocate
        return;

    //The timer is in use
    if(timer_pending(&newdev->timer))
        return;

    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    timer_mod(&newdev->timer,now+backoff_time*newdev->timeslot_duration);

}

static void newdev_realize(PCIDevice *pdev, Error **errp)
{
    NewdevState *newdev = NEWDEV(pdev);
    uint8_t *pci_conf = pdev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    /* Init memory mapped memory region, to expose eBPF programs. */
    memory_region_init_io(&newdev->mmio, OBJECT(newdev), &newdev_bufmmio_ops, newdev,
                    "newdev-buf", NEWDEV_PCI_BAR_SIZE * sizeof(uint32_t));
    pci_register_bar(pdev, NEWDEV_BUF_PCI_BAR, PCI_BASE_ADDRESS_SPACE_MEMORY, &newdev->mmio);

    newdev->buf         = malloc(NEWDEV_BUF_SIZE * sizeof(uint32_t));
    newdev->write_buf   = malloc(NEWDEV_WRITE_BUF_SIZE * sizeof(uint32_t));

    //set_fd_handler?
    newdev->listen_fd = -1;
    newdev->connect_fd = -1;

    newdev->last_timeslot = 0;
    newdev->global_counter = 0;

    //TODO: rimuovere DEBUG
    newdev->no_reset_counter = 0;

    newdev->user_reading = false;

    //setup ht (default=disabled)
    newdev->hyperthreading_remapping = false;

    newdev->listen_fd = make_socket(9999);
    if (newdev->listen_fd < 0){
        return;
    } 

    DBG("socket fd:\t%d", newdev->listen_fd);

    if (listen(newdev->listen_fd, 1) < 0){
      DBG("listen error\n");
      return;        
    }
    DBG("listen\n");

    qemu_set_fd_handler(newdev->listen_fd, accept_handle_read, NULL, newdev);        
    
    DBG("qemu listen_fd added");

    /* For vCPU Pinning */

    for(int i=0;i<MAX_CPU;i++)
        newdev->vCPU_counter[i] = 0;

    /* For Dynamic RAM */
    //TODO: va fatta lazy, questo codice potrebbe crashare se virtio-mem viene caricato DOPO di me!!!!!!
    Error *err = NULL;

    QString *qstring = (QString *)qmp_qom_get(VIRTIO_MEM_ID,"memdev",&err);

    if(err != NULL){
        error_reportf_err(err,"Error: ");
        return;
        //DBG("Errore! %s\n",err->msg);
    }
    
    const char *qom_mem_backend_path = qstring_get_str(qstring);

    QNum *qnum = (QNum *)qmp_qom_get(qom_mem_backend_path,"size",&err);
    uint64_t max_ram = qnum_get_uint(qnum);
    newdev->max_ram = max_ram;

    DBG("max_ram: %lu MiB\n",newdev->max_ram/MEGA);

    timer_init_ms(&newdev->timer, QEMU_CLOCK_VIRTUAL, timer_callback, newdev);
    DBG("**** device realized ****");

}

static void newdev_uninit(PCIDevice *pdev)
{
    NewdevState *newdev = NEWDEV(pdev);

    free(newdev->buf);
    free(newdev->write_buf);

    //unset_fd_handler
    if (newdev->listen_fd != -1) {
        qemu_set_fd_handler(newdev->listen_fd, NULL, NULL, NULL);
        qemu_close(newdev->listen_fd);
    }

    timer_del(&newdev->timer);

    DBG("**** device unrealized ****");
}


static void newdev_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize   = newdev_realize;
    k->exit      = newdev_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = NEWDEV_DEVICE_ID;
    
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void newdev_instance_init(Object *obj){    
 	return;
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
        .interfaces    = interfaces,
    };

    type_register_static(&newdev_info);
}
type_init(newdev_register_types)
