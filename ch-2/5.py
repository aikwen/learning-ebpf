#!/usr/bin/env python3
from bcc import BPF
from time import sleep
from bcc.syscall import syscall_name

program = r"""
BPF_HASH(counter_table);

int hello(struct bpf_raw_tracepoint_args *ctx) {
   u64 syscall_id;
   u64 counter = 0;
   u64 *p;

   syscall_id = ctx->args[1];
   p = counter_table.lookup(&syscall_id);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&syscall_id, &counter);
   return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    print("\n" + "="*40)
    for k, v in b["counter_table"].items():
        try:
            raw_name = syscall_name(k.value)
            name = raw_name.decode() if raw_name else f"Unknown({k.value})"
        except:
            name = f"Unknown({k.value})"

        print(f"{name:<20} : {v.value}")