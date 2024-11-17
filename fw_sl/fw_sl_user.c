#include "fw_sl.h"
#include "fw_sl_kern.skel.h"

#include <signal.h>
#include <string.h> /* strerror */
#include <unistd.h>

#define ERR(fmt, ...)                                                          \
    do {                                                                       \
        fprintf(stderr, "ERROR: %s: " fmt "\n", __func__, ##__VA_ARGS__);      \
    } while ( 0 )

/* struct for wrapping all bpf program information - for example skeleton for
 * loading and cleanup */
struct fw_bpf_prog {
    struct fw_sl_kern_bpf *skel;
};

int unload_bpf_prog(struct fw_bpf_prog *prog) {
    fw_sl_kern_bpf__destroy(prog->skel);
    prog->skel = NULL;
}

int load_bpf_prog(struct fw_bpf_prog *prog) {
    struct fw_sl_kern_bpf *skel = prog->skel;
    int                    err;

    skel = fw_sl_kern_bpf__open_and_load();
    if ( skel == NULL ) {
        ERR("Couldn't open and load BPF program");
        return -1;
    }

    /* short explanation about cleanup: cleaned up when userspace program exits
     */
    err = fw_sl_kern_bpf__attach(skel);
    if ( err < 0 ) {
        ERR("Failed attaching program: %s", strerror(errno));
        goto cleanup_load;
    }

    return 0;

cleanup_load:
    unload_bpf_prog(prog);

    return -1;
}

static struct fw_bpf_prog prog;

void sigint_handler(int sig) {
    if ( prog.skel != NULL ) unload_bpf_prog(&prog);

    exit(1);
}

int main(void) {
    struct fw_sl_kern_bpf *skel;
    int                    queue_map_fd, pkt_dec_fd;
    int                    err;

    signal(SIGINT, sigint_handler);

    err = load_bpf_prog(&prog); /* inits prog.skel */
    if ( err < 0 ) {
        ERR("Couldn't load bpf program");
        exit(1);
    }
    skel = prog.skel;

    struct bpf_map    *pkt_dec_map = skel->maps.pkt_decision;
    struct bpf_map    *queue_map   = skel->maps.preprocess_pkts;
    struct packet_info pkt;
    enum pkt_decision  dc = PKT_NODC;

    while ( true ) {
        err = bpf_map__lookup_elem(queue_map, 0, 0, &pkt, sizeof(pkt), 0);
        if ( err < 0 ) {
            printf("queue empty\n");
        }

        if ( pkt.port_dst == 22 )
            dc = PKT_PASS;
        else
            dc = PKT_DROP;

        err = bpf_map__update_elem(pkt_dec_map, &pkt.pkt_dec_map_index,
                                   sizeof(pkt.pkt_dec_map_index), &dc,
                                   sizeof(dc), 0);
        if ( err < 0 ) {
            /* unrecoverable error, must be bad key */
            goto cleanup_queue_map;
        }
    }

cleanup_queue_map:
    // close(queue_map_fd);
cleanup_pkt_dec_map:
    // close(pkt_dec_fd);
cleanup_load:
    unload_bpf_prog(&prog);
}
