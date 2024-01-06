#include "utils.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} msg_ringbuf SEC(".maps");

#define MSG_LEN 64
typedef struct {
    char msg[MSG_LEN + 1];
} msg_ent_t;

#define SEND_MSG(format, ...)                                        \
    do {                                                             \
        msg_ent_t *ringbuf_ent =                                     \
            bpf_ringbuf_reserve(&msg_ringbuf, sizeof(msg_ent_t), 0); \
        if (ringbuf_ent) {                                           \
            BPF_SNPRINTF(ringbuf_ent->msg, MSG_LEN + 1, format,      \
                         ##__VA_ARGS__);                             \
            bpf_ringbuf_submit(ringbuf_ent, 0);                      \
        }                                                            \
    } while (0);
