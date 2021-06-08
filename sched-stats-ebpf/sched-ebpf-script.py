#!/usr/bin/python
#

from __future__ import print_function
from bcc import BPF
import time

# load BPF program
b = BPF(text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

struct data_t {
    int pid;
    int tid;
    char name[TASK_COMM_LEN];
};

struct details_t {
    int disp;
    int cpu;
    int affin;
    int oc;
    int sc;
    int bc;
};
    
BPF_HASH(key, struct data_t, struct details_t, 1000000);

TRACEPOINT_PROBE(sched, sched_switch) {
    struct data_t data = {};
    struct details_t leaf = {};
    struct details_t *lookup_data;
    int cpu, old_bc, new_bc;
    int common_cpu = bpf_get_smp_processor_id();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid();
    bpf_probe_read_kernel_str(&(data.name), sizeof(data.name), &(args->prev_comm));
    
    lookup_data = key.lookup(&data);
    if (lookup_data != 0) {
        cpu = lookup_data->cpu;
        lookup_data->disp += 1;
        if (lookup_data->cpu == common_cpu)
            lookup_data->affin += 1;
        else {
            old_bc = (int)(cpu/8);
            new_bc = (int)(common_cpu/8);
            if (old_bc != new_bc)
                lookup_data->oc += 1;
            else {
                if ((int)(cpu % 2) == (int)(common_cpu % 2))
                    lookup_data->sc += 1;
                else
                    lookup_data->bc += 1;
            }
        }
        lookup_data->cpu = common_cpu;
        key.update(&data, lookup_data); 
    } else {
        leaf.cpu = common_cpu;
        leaf.disp = 1;
        leaf.affin = 1;
        leaf.sc = 0;
        leaf.bc = 0;
        leaf.oc = 0;
        key.insert(&data, &leaf);
    }

    return 0;
}
""")

print("Sleeping for 10 secs")
time.sleep(10)
print("%s %12s %8s %8s %8s %12s %8s %6s %8s %6s %8s %6s" % ("Process", "tid", "pid", "#Disp", "#affin", "%affin", "#sc", "%sc", "#bc", "%bc", "#oc", "%oc"))
print("-------------------------------------------------------------------------------------------------------------------")
for (k, v) in b.get_table('key').items():
    print('{:<16s} {:<8d} {:<8d} {:<8d} {:<8d} {:<8.2f} {:<10d} {:<8.2f} {:<8d} {:<6.2f} {:<8d} {:<6.2f} '.format(
        k.name.decode('utf-8', 'replace'), k.pid, k.tid, v.disp,
        v.affin, (v.affin*100/v.disp),
        v.sc, (v.sc*100/v.disp),
        v.bc, (v.bc*100/v.disp),
        v.oc, (v.oc*100/v.disp)))

exit()

