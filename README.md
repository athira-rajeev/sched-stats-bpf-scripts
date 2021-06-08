# sched-stats-bpf-scripts


ebpf script to understand schedular strategey.

Uses tracepoint sched:sched_switch via TRACEPOINT_PROBE in bcc python script and
uses same approach as in https://github.com/maddy-kerneldev/sched-stats-scripts.
And outputs details like tid, pid, number of dispatches, affinity, %affinity along with
count on same cache core (sc), big core(bc) and other core(oc) scheduling. 

Usage:
python sched-ebpf-script.py

Pre-requisite:
Needs bcc and python-bcc
