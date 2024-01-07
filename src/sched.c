/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <bpf/bpf.h>
#include <fcntl.h>
#include <libgen.h>
#include <scx/common.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sched.bpf.skel.h"

const char help_fmt[] =
    "A simple sched_ext scheduler.\n"
    "\n"
    "See the top-level comment in .bpf.c for more details.\n"
    "\n"
    "Usage: %s [-f] [-p]\n"
    "\n"
    "  -h            Display this help and exit\n";

static volatile int exit_req;

static void sigint_handler(int simple)
{
    exit_req = 1;
}

static void read_stats(struct sched_bpf *skel, __u64 *stats)
{
    int nr_cpus = libbpf_num_possible_cpus();
    __u64 cnts[2][nr_cpus];
    __u32 idx;

    memset(stats, 0, sizeof(stats[0]) * 2);

    for (idx = 0; idx < 2; idx++) {
        int ret, cpu;

        ret =
            bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts[idx]);
        if (ret < 0)
            continue;
        for (cpu = 0; cpu < nr_cpus; cpu++)
            stats[idx] += cnts[idx][cpu];
    }
}

#define MSG_LEN 64
typedef struct {
    char msg[MSG_LEN + 1];
} msg_ent_t;

static int handle_msg(void *ctx, void *data, size_t data_sz)
{
    msg_ent_t *ent = data;
    puts(ent->msg);
}

int main(int argc, char **argv)
{
    struct sched_bpf *skel;
    struct bpf_link *link;
    __u32 opt;
    ssize_t r;
    char buf[256];

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    int fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
    SCX_BUG_ON(!fd, "Failed to open trace_pipe");

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = sched_bpf__open();
    SCX_BUG_ON(!skel, "Failed to open skel");

    while ((opt = getopt(argc, argv, "fph")) != -1) {
        switch (opt) {
        case 'h':
        default:
            fprintf(stderr, help_fmt, basename(argv[0]));
            return opt != 'h';
        }
    }

    SCX_BUG_ON(sched_bpf__load(skel), "Failed to load skel");

    link = bpf_map__attach_struct_ops(skel->maps.simple_ops);
    SCX_BUG_ON(!link, "Failed to attach struct_ops");

    while (!exit_req && !uei_exited(&skel->bss->uei)) {
        __u64 stats[2];
        read_stats(skel, stats);
        printf("local=%llu global=%llu\n", stats[0], stats[1]);
        fflush(stdout);

        if (r = read(fd, buf, 256)) {
            buf[r] = 0;
            printf("%s\n", buf);
        }
        sleep(1);
    }

    close(fd);
    bpf_link__destroy(link);
    uei_print(&skel->bss->uei);
    sched_bpf__destroy(skel);
    return 0;
}
