import me.bechberger.ebpf.bcc.BPF;

/**
 * Most basic example
 */

public class Hello {
    public static void main(String[] args) {
        try (BPF b = BPF.builder("""
                int kprobe__sys_clone(void *ctx) {
                   bpf_trace_printk("Salut Devoxx! 
                   Je suis un programme ebpf");
                   return 0;
                }
                """).build()) {
            b.trace_print();
        }
    }
}