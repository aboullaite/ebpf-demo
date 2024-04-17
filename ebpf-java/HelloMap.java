import me.bechberger.ebpf.bcc.BPF;
import me.bechberger.ebpf.bcc.BPFTable;

import static me.bechberger.ebpf.bcc.BPFTable.HashTable.UINT64T_MAP_PROVIDER;

/**
 * Count and print `execve` calls per user
 */

public class HelloMap {
    public static void main(String[] args) throws InterruptedException {
        try (var b = BPF.builder("""
                BPF_HASH(counter_table);
                
                int hello(void *ctx) {
                   u64 uid;
                   u64 counter = 0;
                   u64 *p;
                
                   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                   p = counter_table.lookup(&uid);
                   if (p != 0) {
                      counter = *p;
                   }
                   counter++;
                   counter_table.update(&uid, &counter);
                   return 0;
                }
                """).build()) {
            var syscall = b.get_syscall_fnname("execve");
            b.attach_kprobe(syscall, "hello");
            BPFTable.HashTable<Long, Long> counterTable = b.get_table("counter_table", UINT64T_MAP_PROVIDER);
            while (true) {
                Thread.sleep(2000);
                for (var entry : counterTable.entrySet()) {
                    System.out.printf("ID %d: %d\t", entry.getKey(), entry.getValue());
                }
                System.out.println();
            }
        }
    }
}