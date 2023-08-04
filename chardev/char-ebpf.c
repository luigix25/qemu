#include <sys/timerfd.h>
#include "qemu/osdep.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "chardev/char-fd.h"
#include "chardev/char-io.h"
#include "io/channel-buffer.h"


#define CHAR_EBPF_DEBUG 1

#if CHAR_EBPF_DEBUG > 0
#define DBG(fmt, ...) do { \
        fprintf(stderr, "char-ebpf: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...)
#endif


struct eBPFChardev {
    FDChardev parent;
    uint32_t last_byte_read;
};
typedef struct eBPFChardev eBPFChardev;

DECLARE_INSTANCE_CHECKER(eBPFChardev, EBPF_CHARDEV,
                         TYPE_CHARDEV_EBPF)


static void char_ebpf_parse(QemuOpts *opts, ChardevBackend *backend,
                                Error **errp)
{
    DBG("parse! %d",backend->type);

    ChardevHostdev *dev;

    backend->type = CHARDEV_BACKEND_KIND_EBPF;
    dev = backend->u.ebpf.data = g_new0(ChardevHostdev, 1);
    qemu_chr_parse_common(opts, qapi_ChardevHostdev_base(dev));
}

static void char_ebpf_open(Chardev *chr,
                               ChardevBackend *backend,
                               bool *be_opened,
                               Error **errp)
{

    eBPFChardev *bpf = EBPF_CHARDEV(chr);
    FDChardev *s = FD_CHARDEV(chr);


    DBG("open! %d",backend->type);
    *be_opened = true;

    s->ioc_in = QIO_CHANNEL(qio_channel_buffer_new(4096));

    const char *name = "prova prova\n";
    qio_channel_set_name(QIO_CHANNEL(s->ioc_in), name);

    int ret;
    ret = qio_channel_write(s->ioc_in, name, strlen(name), NULL);

    printf("qio_channel_write %d\n",ret);

    bpf->last_byte_read = 0;

}

static int char_ebpf_write(Chardev *s, const uint8_t *buf, int len){


    DBG("write!");
    DBG("%s",buf);

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

    //ret = qio_channel_read(chan, (gchar *)buf, len, NULL);

    printf("Provo a leggere %d da %s, Letti %d da channel read\n",len,chan->name,len);

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
