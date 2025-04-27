from bcc import BPF

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct filename_t {
    char name[256];
};

BPF_HASH(open_filenames, u64, struct filename_t);
BPF_HASH(mem_fds, u64, u8);

static inline size_t custom_strlen(const char *str) {
    size_t len = 0;
    while (str[len] != '\\0' && len < 256) {
        len++;
    }
    return len;
}

static inline int starts_with(const char *str, const char *prefix) {
    int i;
    for (i = 0; prefix[i] != '\\0'; i++) {
        if (str[i] != prefix[i]) {
            return 0;
        }
    }
    return 1;
}

static inline int ends_with(const char *str, const char *suffix) {
    size_t str_len = custom_strlen(str);
    size_t suffix_len = custom_strlen(suffix);
    if (str_len < suffix_len) {
        return 0;
    }
    for (size_t i = 0; i < suffix_len; i++) {
        if (str[str_len - suffix_len + i] != suffix[i]) {
            return 0;
        }
    }
    return 1;
}

int trace_enter_openat(struct tracepoint__syscalls__sys_enter_openat *args) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct filename_t fn = {};
    bpf_probe_read_str(fn.name, sizeof(fn.name), (void *)args->filename);
    open_filenames.update(&pid_tgid, &fn);
    return 0;
}

int trace_exit_openat(struct tracepoint__syscalls__sys_exit_openat *args) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct filename_t *fn = open_filenames.lookup(&pid_tgid);
    if (fn) {
        if (starts_with(fn->name, "/proc/") && ends_with(fn->name, "/mem")) {
            if (args->ret >= 0) {
                u32 pid = pid_tgid >> 32;
                u32 fd = args->ret;
                u64 key = ((u64)pid << 32) | fd;
                u8 val = 1;
                mem_fds.update(&key, &val);
            }
        }
        open_filenames.delete(&pid_tgid);
    }
    return 0;
}

int trace_enter_write(struct tracepoint__syscalls__sys_enter_write *args) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 fd = args->fd;
    u64 key = ((u64)pid << 32) | fd;
    u8 *val = mem_fds.lookup(&key);
    if (val) {
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        bpf_trace_printk("PID %d (%s) writing to /proc/$PID/mem fd %d\\n", pid, comm, fd);
    }
    return 0;
}

int trace_enter_execve(struct tracepoint__syscalls__sys_enter_execve *args) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char filename[256];
    bpf_probe_read_str(filename, sizeof(filename), (void *)args->filename);
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_trace_printk("PID %d (%s) execve %s\\n", pid, comm, filename);
    return 0;
}
"""

b = BPF(text=bpf_program)

b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_enter_openat")
b.attach_tracepoint(tp="syscalls:sys_exit_openat", fn_name="trace_exit_openat")
b.attach_tracepoint(tp="syscalls:sys_enter_write", fn_name="trace_enter_write")
b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_enter_execve")

print("Tracing system calls... Ctrl-C to end.")
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(msg.decode('utf-8', 'replace'))
    except ValueError:
        continue
    except KeyboardInterrupt:
        print("\nTracing stopped.")
        break
