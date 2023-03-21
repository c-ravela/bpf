//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include <bpf/bpf_tracing.h>

struct bpf_map_def SEC("maps") event = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

struct event_data
{
    __u8 comm[16];
    __u64 exec_id;
    __u32 pid;
    __u32 tgid;
    __s32 on_rq;
    __s32 on_cpu;
    __u32 state;
    __s32 wake_cpu;
    __s32 recent_used_cpu;
    __s32 prio;
    __s32 normal_prio;
    __s32 static_prio;
    __u32 rt_priority;
    __u32 policy;
    __s32 nr_cpus_allowed;
    __s32 exit_state;
    __s32 exit_code;
    __s32 exit_signal;
    __s32 pdeath_signal;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int task(struct pt_regs *ctx){

    struct event_data ed = {};
    struct task_struct *task;
    char com[80];

    task = (struct task_struct *)bpf_get_current_task();

    // bpf_probe_read(&pid_link, sizeof(pid_link), (void *)&task->group_leader->pids[PIDTYPE_SID]);    
    // bpf_probe_read(&pid, sizeof(pid), (void *)pid_link.pid);

    bpf_probe_read_kernel(&ed.comm , sizeof(ed.comm), &task->comm);
    bpf_probe_read_kernel(&ed.exec_id, sizeof(ed.exec_id), &task->parent_exec_id);
    bpf_probe_read_kernel(&ed.pid, sizeof(ed.pid), &task->pid);
    bpf_probe_read_kernel(&ed.tgid, sizeof(ed.tgid), &task->tgid);
    bpf_probe_read_kernel(&ed.on_rq, sizeof(ed.on_rq), &task->on_rq);
    bpf_probe_read_kernel(&ed.on_cpu, sizeof(ed.on_cpu), &task->on_cpu);
    bpf_probe_read_kernel(&ed.state, sizeof(ed.state), &task->__state);
    bpf_probe_read_kernel(&ed.wake_cpu, sizeof(ed.wake_cpu), &task->wake_cpu);
    bpf_probe_read_kernel(&ed.recent_used_cpu, sizeof(ed.recent_used_cpu), &task->recent_used_cpu);
    bpf_probe_read_kernel(&ed.prio, sizeof(ed.prio), &task->prio);
    bpf_probe_read_kernel(&ed.normal_prio, sizeof(ed.normal_prio), &task->normal_prio);
    bpf_probe_read_kernel(&ed.static_prio, sizeof(ed.static_prio), &task->static_prio);
    bpf_probe_read_kernel(&ed.rt_priority, sizeof(ed.rt_priority), &task->rt_priority);
    bpf_probe_read_kernel(&ed.policy, sizeof(ed.policy), &task->policy);
    bpf_probe_read_kernel(&ed.nr_cpus_allowed, sizeof(ed.nr_cpus_allowed), &task->nr_cpus_allowed);
    bpf_probe_read_kernel(&ed.exit_state, sizeof(ed.exit_state), &task->exit_state);
    bpf_probe_read_kernel(&ed.exit_code, sizeof(ed.exit_code), &task->exit_code);
    bpf_probe_read_kernel(&ed.exit_signal, sizeof(ed.exit_signal), &task->exit_signal);
    bpf_probe_read_kernel(&ed.pdeath_signal, sizeof(ed.pdeath_signal), &task->pdeath_signal);

    // u64 arg1 = PT_REGS_PARM1(ctx);
    // bpf_printk("sys_clone called with arg1=%lu\n", arg1);

    long unsigned int r15;
    bpf_probe_read_kernel(&r15, sizeof(r15), &ctx->r15);


    bpf_printk("CR Trace: %lld", r15);

    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &ed, sizeof(ed));

    return 0;
};

char _license[] SEC("license") = "Dual MIT/GPL";