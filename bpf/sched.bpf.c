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
UEI_DEFINE(uei);

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

static bool task_node_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
    struct task_node *ta, *tb;

    ta = container_of(a, struct task_node, rb_node);
    tb = container_of(b, struct task_node, rb_node);

    return ta->vtime < tb->vtime;
}

static void vtime_tree_add(struct task_node *node)
{
    bpf_spin_lock(&vtime_tree_lock);
    bpf_rbtree_add(&vtime_tree, &node->rb_node, task_node_less);
    bpf_spin_unlock(&vtime_tree_lock);
}

static struct task_node *vtime_tree_remove_first()
{
    bpf_spin_lock(&vtime_tree_lock);
    struct bpf_rb_node *rb_node = bpf_rbtree_first(&vtime_tree);
    if (!rb_node) {
        bpf_spin_unlock(&vtime_tree_lock);
        bpf_printk("empty rbtree");
        return NULL;
    }

    rb_node = bpf_rbtree_remove(&vtime_tree, rb_node);
    bpf_spin_unlock(&vtime_tree_lock);
    if (!rb_node) {
        /*
         * This should never happen. bpf_rbtree_first() was called
         * above while the tree lock was held, so the node should
         * always be present.
         */
        scx_bpf_error("node could not be removed");
        return NULL;
    }

    return container_of(rb_node, struct task_node, rb_node);
}

static void do_enqueue(struct task_struct *p)
{
    pid_t pid = p->pid;

    bpf_printk("enqueue pid=%d", pid);

    // Create node for the task
    struct task_node *node = bpf_obj_new(struct task_node);
    if (!node) {
        scx_bpf_error("unexpected node allocated error");
        goto err_end;
    }

    node->pid = pid;
    node->vtime = p->scx.dsq_vtime;

    vtime_tree_add(node);

    bpf_printk("enqueue pid=%d success", pid);
    return;

err_end:
    bpf_printk("enqueue pid=%d fail", pid);
    return;
}

static struct task_struct *do_dequeue()
{
    bpf_printk("dequeue");

    struct task_node *node = vtime_tree_remove_first();
    if (!node)
        goto err_end;

    pid_t pid = node->pid;
    bpf_obj_drop(node);

    struct task_struct *p = bpf_task_from_pid(pid);
    if (!p)
        goto err_end;

    bpf_printk("dequeue pid=%d success\n", pid);
    return p;

err_end:
    bpf_printk("dequeue fail");
    return NULL;
}


s32 BPF_STRUCT_OPS(simple_select_cpu,
                   struct task_struct *p,
                   s32 prev_cpu,
                   u64 wake_flags)
{
    /* We no longer pass SCX_ENQ_LOCAL to .enqueue() when the default CPU
     * selection has found a core to schedule. Callers can instead use
     * scx_bpf_select_cpu_dfl() to get the same behavior and then
     * decide whether to direct dispatch or not. */
    bool is_idle = false;

    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (is_idle) {
        stat_inc(0); /* count local queueing */
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    stat_inc(1); /* count global queueing */

    u64 vtime = p->scx.dsq_vtime;

    /*
     * Limit the amount of budget that an idling task can accumulate
     * to one slice.
     */
    if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
        p->scx.dsq_vtime = vtime_now - SCX_SLICE_DFL;

    do_enqueue(p);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
    bpf_printk("dispatch start");

    struct task_struct *p = do_dequeue();
    if (!p) {
        return;
    }

    scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
    bpf_printk("dispatch pid=%d success", p->pid);
    bpf_task_release(p);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
    bpf_printk("running pid=%d", p->pid);
    /*
     * Global vtime always progresses forward as tasks start executing. The
     * test and update can be performed concurrently from multiple CPUs and
     * thus racy. Any error should be contained and temporary. Let's just
     * live with it.
     */
    if (vtime_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
    bpf_printk("stopping pid=%d", p->pid);
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
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    /* By default, all SCHED_EXT, SCHED_OTHER, SCHED_IDLE, and
     * SCHED_BATCH tasks should use sched_ext. */
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops simple_ops = {
    .select_cpu = (void *) simple_select_cpu,
    .enqueue = (void *) simple_enqueue,
    .dispatch = (void *) simple_dispatch,
    .running = (void *) simple_running,
    .stopping = (void *) simple_stopping,
    .enable = (void *) simple_enable,
    .init = (void *) simple_init,
    .exit = (void *) simple_exit,
    .name = "simple",
};
