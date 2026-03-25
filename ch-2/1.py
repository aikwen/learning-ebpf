#!/usr/bin/python3
from bcc import BPF

p = r"""
BPF_PERF_OUTPUT(output);

struct data_t {
    u32 pid;
    u32 uid;
    char command[16];
    char message[12];
};

int hello(void *ctx){
    struct data_t data = {};
    char message1[12] = "pid is even";
    char message2[12] = "pid is odd";
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(data.command, sizeof(data.command));
    if ((data.pid & 0x1) == 0){
        bpf_probe_read_kernel(data.message, sizeof(data.message), message1);
    }else{
        bpf_probe_read_kernel(data.message, sizeof(data.message), message2);
    }


    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=p)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# 定义回调函数
def event(cpu, data, size):
    data = b["output"].event(data)
    print(f"pid: {data.pid}\tuid:{data.uid}\tcommand:{data.command.decode()}\t{data.message.decode()}")

b["output"].open_perf_buffer(event)
while True:
    b.perf_buffer_poll()