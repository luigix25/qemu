#include "qemu/osdep.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "chardev/char-fd.h"
#include "chardev/char-io.h"
#include "io/channel-buffer.h"
#include "io/net-listener.h"
#include "qemu/sockets.h"
#include "hw/misc/bpf_injection_msg.h"


#define CHAR_EBPF_DEBUG 1

#if CHAR_EBPF_DEBUG > 0
#define DBG(fmt, ...) do { \
        fprintf(stderr, "char-ebpf: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...)
#endif

#define CHARDEV_BPF_BUF_LEN 4096

#define MAX_SERVICES 10

struct eBPFChardev {
    FDChardev parent;
    uint32_t last_byte_read;
    QIONetListener *listener;
    SocketAddress *addr;
    uint8_t *buffer;
    QIOChannel *sockets[MAX_SERVICES];

};
typedef struct eBPFChardev eBPFChardev;

DECLARE_INSTANCE_CHECKER(eBPFChardev, EBPF_CHARDEV,
                         TYPE_CHARDEV_EBPF)


/*
static void hexdump(const void* data, size_t size);

static void hexdump(const void* data, size_t size){
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

*/
static void char_ebpf_parse(QemuOpts *opts, ChardevBackend *backend, Error **errp){
    DBG("parse! %d",backend->type);

    ChardevHostdev *dev;

    backend->type = CHARDEV_BACKEND_KIND_EBPF;
    dev = backend->u.ebpf.data = g_new0(ChardevHostdev, 1);
    qemu_chr_parse_common(opts, qapi_ChardevHostdev_base(dev));
}


static void add_service(eBPFChardev *bpf, QIOChannel *ioc, uint32_t type){

    if(bpf->sockets[type] == NULL) { //free
        bpf->sockets[type] = ioc;
    } else { //something strange happened
        DBG("Service already loaded!!");
    }

}


static void remove_service(eBPFChardev *bpf, QIOChannel *ioc){

    for(uint32_t i=0;i<MAX_SERVICES;i++){
        if(bpf->sockets[i] == ioc){
            bpf->sockets[i] = NULL;
            return;
        }
    }

    DBG("Service not present!!");
}

static QIOChannel* find_channel(eBPFChardev *ebpf, uint8_t service){
    return ebpf->sockets[service];
}

static int32_t do_read(QIOChannel *ioc, void *opaque){
    Chardev *chr = opaque;
    eBPFChardev *bpf = EBPF_CHARDEV(chr);
    FDChardev *s = FD_CHARDEV(chr);

    int32_t ret;

    ret = qio_channel_read(ioc, (char*)bpf->buffer, sizeof(struct bpf_injection_msg_header), NULL);
    printf("[header] letti %d\n",ret);

    if(ret == 0)
        goto handle_close;

    if(ret < sizeof(struct bpf_injection_msg_header)){
        DBG("ouch ouch ouch");
        return false;
    }

    struct bpf_injection_msg_header *header;
    header = (struct bpf_injection_msg_header *)bpf->buffer;

    uint8_t service = header->service;

    ret = qio_channel_write(s->ioc_in,(const char*)bpf->buffer,sizeof(struct bpf_injection_msg_header),NULL);

    int32_t to_read = header->payload_len;
    uint32_t free_space = CHARDEV_BPF_BUF_LEN;
    uint32_t can_read;

    uint32_t len = 0;
    uint8_t *buf_ptr = bpf->buffer;

    while(to_read > 0){

        if(to_read > free_space)
            can_read = free_space;
        else
            can_read = to_read;

        len = qio_channel_read(ioc, (char*)buf_ptr, can_read, NULL);
        to_read -= len;
        buf_ptr += len;

        DBG("Received some data can_read: %d to_read: %d len: %d\n",can_read,to_read,len);

        if(len <= 0)
            goto handle_close;

        int32_t written;
        uint8_t *buffer_ptr = bpf->buffer;

        while(len > 0){

            written = qio_channel_write(s->ioc_in,(const char*)buffer_ptr,len,NULL);
            if(written <= 0){
                DBG("WRITTEN <= 0 BOH!\n");
                return false;
            }

            len -= written;
            buffer_ptr += written;

        }

        buf_ptr = bpf->buffer;
        free_space = CHARDEV_BPF_BUF_LEN;

    }

    add_service(bpf,ioc,service);
    return 0;


handle_close:
    DBG("dovrei chiudere socket");
    remove_service(bpf,ioc);

    return -1;

}
gboolean ebpf_client_io(QIOChannel *ioc G_GNUC_UNUSED, GIOCondition condition, void *opaque);

gboolean ebpf_client_io(QIOChannel *ioc G_GNUC_UNUSED, GIOCondition condition, void *opaque){

    if (condition & (G_IO_HUP | G_IO_ERR)) {
        printf("vorrei chiudere\n");
        goto handle_close_io;
    }

    int ret;


    if (condition & G_IO_IN) {
        printf("vorrei leggere da socket\n");

        ret = do_read(ioc,opaque);
        if(ret < 0)
            goto handle_close_io;

    } else if (condition & G_IO_OUT) {
        printf("vorrei scrivere su socket\n");
    }


    return TRUE;

handle_close_io:
    printf("Chiudo socket\n");
    qio_channel_close(ioc, NULL);

    return FALSE;

}

static void tcp_chr_accept(QIONetListener *listener, QIOChannelSocket *cioc, void *opaque){

    DBG("connesso!!! fd: %d",cioc->fd);

    QIOChannel *ioc = QIO_CHANNEL(cioc);

    qio_channel_add_watch(
            ioc, G_IO_IN | G_IO_HUP | G_IO_ERR,
            ebpf_client_io, opaque, NULL);

}

static void char_ebpf_open(Chardev *chr,
                               ChardevBackend *backend,
                               bool *be_opened,
                               Error **errp)
{

    eBPFChardev *bpf = EBPF_CHARDEV(chr);
    FDChardev *s = FD_CHARDEV(chr);

    *be_opened = true;

    s->ioc_in = QIO_CHANNEL(qio_channel_buffer_new(4096));
    bpf->listener = qio_net_listener_new();
    qio_net_listener_set_name(bpf->listener, "ebpf-listener");

    bpf->addr = g_new0(SocketAddress, 1);
    InetSocketAddress *inet;
    bpf->addr->type = SOCKET_ADDRESS_TYPE_INET;
    inet = &bpf->addr->u.inet;
    inet->host = g_strdup("127.0.0.1");
    inet->port = g_strdup("9999");

    *errp = NULL;

    if (qio_net_listener_open_sync(bpf->listener, bpf->addr, 1, errp) < 0) {
        DBG("effess");
        object_unref(OBJECT(bpf->listener));
        bpf->listener = NULL;
        g_free(bpf->addr);
        return;
    }


    bpf->buffer = (uint8_t*)malloc(CHARDEV_BPF_BUF_LEN);
    if(!bpf->buffer){
        DBG("errore malloc!");
        return;
    }

    //Every accept tcp_chr_accept is called
    qio_net_listener_set_client_func(bpf->listener, tcp_chr_accept, bpf, NULL);

    /*
    const char *name = ">prova prova<";
    qio_channel_set_name(QIO_CHANNEL(s->ioc_in), name);

*/
    bpf->last_byte_read = 0;

    for(uint32_t i=0;i<MAX_SERVICES;i++){
        bpf->sockets[i] = NULL;
    }

}

static void forward_data_to_service(Chardev *s, uint8_t service, const uint8_t *buf, int len){

    eBPFChardev *ebpf = EBPF_CHARDEV(s);
    QIOChannel *channel = find_channel(ebpf,service);
    if(channel == NULL){
        printf("decisamente strano\n");
        return;
    }
    int ret = qio_channel_write(channel,(char*)buf,len,NULL);

    if(ret <= 0){
        printf("problema!\n");
    }

}

static int char_ebpf_write(Chardev *s, const uint8_t *buf, int len){

    struct bpf_injection_msg_header *header_ptr = (struct bpf_injection_msg_header *)buf;
    uint8_t type = header_ptr->type;

    printf("Ricevuti dati dal guest: version %d type %d payload_length %d service %d\n", header_ptr->version,header_ptr->type, header_ptr->payload_len, header_ptr->service);


   if(type == PROGRAM_INJECTION_RESULT){
        printf("ricevuti risultati!\n");
        uint8_t service = header_ptr->service;
        //uint8_t *payload = buf + sizeof(header_ptr);

        if(service == VCPU_PINNING_TYPE){
            DBG("vcpu");

        } else if(service == DYNAMIC_MEM_TYPE){
            DBG("memory");
            //dynamic_memory(newdev,payload,size);
        } else if(service == FIREWALL_TYPE){
            DBG("firewall");
            //firewall_op(newdev,payload,size);
        }

    }

    forward_data_to_service(s,header_ptr->service,buf,len);


    //DBG("write!");
    return len;
}


static int quanti_byte(void *opaque)
{

    Chardev *chr = CHARDEV(opaque);
    FDChardev *s = FD_CHARDEV(opaque);

    s->max_size = qemu_chr_be_can_write(chr);
    return s->max_size;
}

static gboolean leggi(QIOChannel *chan, GIOCondition cond, void *opaque)
{
    /* Copia della read di char-fd*/
    Chardev *chr = CHARDEV(opaque);
    FDChardev *s = FD_CHARDEV(opaque);
    eBPFChardev *ebpf = EBPF_CHARDEV(opaque);

    QIOChannelBuffer *bioc = QIO_CHANNEL_BUFFER(s->ioc_in);

    int len;
    uint8_t buf[CHR_READ_BUF_LEN];

    len = sizeof(buf);
    if (len > s->max_size) {
        len = s->max_size;
    }
    if (len == 0 || bioc->offset == ebpf->last_byte_read) {
        return TRUE;
    }

    /*
    if(bioc->offset == ebpf->last_byte_read){ //nulla da leggere
        printf("nulla da leggere\n");
        remove_fd_in_watch(chr);
        qemu_chr_be_event(chr, CHR_EVENT_CLOSED);
        qemu_chr_be_event(chr, CHR_EVENT_OPENED);

        return FALSE;
    }*/

    if(len > (bioc->offset - ebpf->last_byte_read)){
        len = bioc->offset - ebpf->last_byte_read;
    }


    uint8_t *buffer = bioc->data + ebpf->last_byte_read;
    memcpy(buf,buffer,len);
    ebpf->last_byte_read += len;

    printf("Provo a leggere %d, Letti %d da channel read\n",len,len);

    qemu_chr_be_write(chr, buf, len);

    return TRUE;
}


static void chr_ebpf_update_read_handler(Chardev *chr){

    FDChardev *s = FD_CHARDEV(chr);

    remove_fd_in_watch(chr);
    chr->gsource = io_add_watch_poll(chr, s->ioc_in,
                                     quanti_byte,
                                     leggi, chr,
                                     chr->gcontext);

}

static void chr_ebpf_set_fe_open(Chardev *chr, int fe_open){

    if(fe_open){
        printf("set open event\n");
        //qemu_chr_be_event(chr, CHR_EVENT_OPENED);
    }

}

static void char_ebpf_class_init(ObjectClass *oc, void *data){

    ChardevClass *cc = CHARDEV_CLASS(oc);
    cc->parse = char_ebpf_parse;
    cc->open = char_ebpf_open;
    cc->chr_write = char_ebpf_write;
    cc->chr_set_fe_open = chr_ebpf_set_fe_open;
    cc->chr_update_read_handler = chr_ebpf_update_read_handler;
}

static const TypeInfo char_socket_type_info = {
    .name = TYPE_CHARDEV_EBPF,
    .parent = TYPE_CHARDEV_FD,
    .instance_size = sizeof(eBPFChardev),
    .class_init = char_ebpf_class_init,
};

static void register_types(void)
{
    type_register_static(&char_socket_type_info);
}

type_init(register_types);
