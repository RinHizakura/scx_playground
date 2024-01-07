/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <asm-generic/errno-base.h>
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

static u64 vtime_now;
struct user_exit_info uei;

#define SHARED_DSQ 0

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 2); /* [local, global] */
} stats SEC(".maps");

/* The following describe a reb-black tree for task, which
 * using the vtime of tasks as key to order them. */
struct task_node {
    struct bpf_rb_node rb_node;
    u64 vtime;
    pid_t pid;
};
private(VTIME_TREE) struct bpf_spin_lock vtime_tree_lock;
private(VTIME_TREE) struct bpf_rb_root vtime_tree
    __contains(task_node, rb_node);

/* This structure manages the dynamic allocated node instance. */
struct task_node_stash {
    struct task_node __kptr *node;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct task_node_stash);
} task_node_stash SEC(".maps");

static void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
    return (s64) (a - b) < 0;
}

static int do_enqueue(pid_t pid)
{
    u64 key = pid;
    int err = 0;
    struct task_node_stash empty_stash = {}, *stash;

    bpf_printk("enqueue pid = %d", pid);

    // Create a new element if the key's related entry is not exist(BPF_NOEXIST)
    err =
        bpf_map_update_elem(&task_node_stash, &key, &empty_stash, BPF_NOEXIST);
    if (err && err != -EEXIST) {
        if (err != -ENOMEM)
            scx_bpf_error("unexpected stash creation error(%d)", err);
        goto err_end;
    }

    // Access the entry in hashmap by the key
    stash = bpf_map_lookup_elem(&task_node_stash, &key);
    if (!stash) {
        scx_bpf_error("unexpected node stash lookup failure");
        err = -ENOENT;
        goto err_end;
    }

    // Create node for the task
    struct task_node *node = bpf_obj_new(struct task_node);
    if (!node) {
        scx_bpf_error("unexpected node allocated error");
        err = -ENOMEM;
        goto err_del_node;
    }

    node->pid = pid;
    node->vtime = vtime_now;

    node = bpf_kptr_xchg(&stash->node, node);
    if (node) {
        scx_bpf_error("unexpected !NULL node stash");
        err = -EBUSY;
        goto err_drop;
    }

    bpf_printk("enqueue pid = %d success", pid);
    return 0;

err_drop:
    bpf_obj_drop(node);
err_del_node:
    bpf_map_delete_elem(&task_node_stash, &key);
err_end:
    bpf_printk("enqueue pid = %d fail", pid);
    return err;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    /*
     * If scx_select_cpu_dfl() is setting %SCX_ENQ_LOCAL, it indicates that
     * running @p on its CPU directly shouldn't affect fairness. Just queue
     * it on the local FIFO.
     */
    if (enq_flags & SCX_ENQ_LOCAL) {
        stat_inc(0); /* count local queueing */
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
        return;
    }

    stat_inc(1); /* count global queueing */

    u64 vtime = p->scx.dsq_vtime;

    /*
     * Limit the amount of budget that an idling task can accumulate
     * to one slice.
     */
    if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
        vtime = vtime_now - SCX_SLICE_DFL;

    do_enqueue(p->pid);

    scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
    /*
     * Global vtime always progresses forward as tasks start executing. The
     * test and update can be performed concurrently from multiple CPUs and
     * thus racy. Any error should be contained and temporary. Let's just
     * live with it.
     */
    if (vtime_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

static int do_dequeue(pid_t pid)
{
    u64 key = pid;
    int err = 0;
    struct task_node_stash *stash;

    bpf_printk("dequeue pid = %d", pid);

    stash = bpf_map_lookup_elem(&task_node_stash, &key);
    if (!stash) {
        bpf_printk("dequeue pid=%d not exist\n", pid);
        return 0;
    }

    struct task_node *node = bpf_kptr_xchg(&stash->node, NULL);
    if (!node) {
        scx_bpf_error("unexpected NULL node stash");
        err = -EBUSY;
        goto err_end;
    }

    bpf_obj_drop(node);

    bpf_printk("dequeue pid=%d success\n", pid);
    return 0;

err_end:
    bpf_printk("dequeue pid=%d fail\n", pid);
    return err;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
    /*
     * Scale the execution time by the inverse of the weight and charge.
     *
     * Note that the default yield implementation yields by setting
     * @p->scx.slice to zero and the following would treat the yielding task
     * as if it has consumed all its slice. If this penalizes yielding tasks
     * too much, determine the execution time by taking explicit timestamps
     * instead of depending on @p->scx.slice.
     */
    p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;

    do_dequeue(p->pid);
}

void BPF_STRUCT_OPS(simple_enable,
                    struct task_struct *p,
                    struct scx_enable_args *args)
{
    p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    scx_bpf_switch_all();

    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
    uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops simple_ops = {
    .enqueue = (void *) simple_enqueue,
    .dispatch = (void *) simple_dispatch,
    .running = (void *) simple_running,
    .stopping = (void *) simple_stopping,
    .enable = (void *) simple_enable,
    .init = (void *) simple_init,
    .exit = (void *) simple_exit,
    .name = "simple",
};
