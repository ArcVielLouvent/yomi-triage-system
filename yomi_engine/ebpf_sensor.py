import os
import sys
import time
import threading

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - eBPF Sentinel
# Purpose: Ring-0 Kernel Interception. Injects C code via LLVM BPF Compiler to
#          trace sys_enter_openat and sys_enter_execve. Uses BPF Hash Maps for
#          zero-overhead, surgically targeted telemetry.
# ==============================================================================


class eBPFSentinel:
    # --------------------------------------------------------------------------
    # SINGLETON PATTERN: Prevents multiple 2-second LLVM compilations.
    # --------------------------------------------------------------------------
    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls):
        with cls._singleton_lock:
            if cls._instance is None:
                # [FIXED] Standard Python 3 way to avoid infinite recursion
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        self.audit = ImmutableStamp()
        self.os_bridge = OSBridge()
        self.bpf_instance = None
        self.is_armed = False

        # ----------------------------------------------------------------------
        # THE KERNEL PAYLOAD (Restricted C with BPF_HASH filtering)
        # ----------------------------------------------------------------------
        self.bpf_program = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        #include <linux/fs.h>

        // BPF Hash map to store PIDs targeted by the Shadow Net
        BPF_HASH(tracked_pids, u32, u32);

        struct data_t {
            u32 pid;
            u32 event_type; // 1 for openat, 2 for execve
            char comm[16];
            char filename[256];
        };

        BPF_PERF_OUTPUT(malicious_events);

        // [FIXED] Kernel modern requires PT_REGS_PARM to extract syscall arguments
        int trace_syscall_openat(struct pt_regs *ctx) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            u32 pid = pid_tgid >> 32;

            u32 *is_tracked = tracked_pids.lookup(&pid);
            if (is_tracked == NULL) {
                return 0; // Ignore benign OS traffic
            }

            struct data_t data = {};
            data.pid = pid;
            data.event_type = 1;

            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            // Extract argument 2 (filename) from openat(dirfd, filename, flags)
            const char __user *filename = (const char __user *)PT_REGS_PARM2(ctx);
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

            malicious_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // [FIXED] Extract execve arguments safely via registers
        int trace_syscall_execve(struct pt_regs *ctx) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            u32 pid = pid_tgid >> 32;

            u32 *is_tracked = tracked_pids.lookup(&pid);
            if (is_tracked == NULL) {
                return 0;
            }

            struct data_t data = {};
            data.pid = pid;
            data.event_type = 2;

            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            // Extract argument 1 (filename) from execve(filename, argv, envp)
            const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

            malicious_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """

    def arm_sensor(self) -> bool:
        if self.is_armed and self.bpf_instance:
            return True

        if self.os_bridge.environment not in [
            "SIFT_LINUX",
            "CODESPACES_LINUX",
            "LINUX",
        ]:
            print(
                "[eBPF] Hardware unsupported for direct Kernel injection. Linux Kernel required."
            )
            return False

        try:
            from bcc import BPF  # type: ignore

            print(
                "[YOMI-eBPF] [VOID BLACK] Compiling C payload via LLVM and injecting into Ring-0 Kernel..."
            )
            self.bpf_instance = BPF(text=self.bpf_program)

            openat_fn = self.bpf_instance.get_syscall_fnname("openat")
            self.bpf_instance.attach_kprobe(
                event=openat_fn, fn_name="trace_syscall_openat"
            )

            execve_fn = self.bpf_instance.get_syscall_fnname("execve")
            self.bpf_instance.attach_kprobe(
                event=execve_fn, fn_name="trace_syscall_execve"
            )

            self.is_armed = True
            print(
                "[YOMI-eBPF] [PLASMA BLUE] eBPF Sentinel Armed. Waiting for targeted PID injection."
            )
            self.audit.record_action(
                "eBPF",
                "ARMED",
                "Kernel trace_syscall_openat and execve injected globally.",
            )
            return True

        except ImportError:
            print(
                "[YOMI-eBPF] [WARNING] BCC library not found. Kernel syscall tracing unavailable."
            )
            return False
        except Exception as e:
            print(
                f"[YOMI-eBPF] [ERROR] Kernel Injection Failed (Root required): {str(e)}"
            )
            return False

    def monitor_pid(self, target_pid: int, duration_sec: int = 3) -> bool:
        if not self.is_armed or not self.bpf_instance:
            print(
                "[YOMI-eBPF] [WARNING] eBPF sensor is not armed. Kernel trace data unavailable."
            )
            return False

        import ctypes

        tracked_pids = self.bpf_instance.get_table("tracked_pids")
        tracked_pids[ctypes.c_uint32(target_pid)] = ctypes.c_uint32(1)

        malicious_intent_found = False

        def print_event(cpu, data, size):
            nonlocal malicious_intent_found
            event = self.bpf_instance["malicious_events"].event(data)  # type: ignore

            filename = event.filename.decode("utf-8", "replace")

            if event.event_type == 1:
                if (
                    "shadow" in filename
                    or "SAM" in filename
                    or "ssh/id_rsa" in filename
                ):
                    print(
                        f"[YOMI-eBPF] [BLOOD RED] KERNEL INTERCEPT: PID {event.pid} accessed restricted file: {filename}"
                    )
                    malicious_intent_found = True
            elif event.event_type == 2:
                if (
                    "bash" in filename
                    or "sh" in filename
                    or "cmd" in filename
                    or "powershell" in filename
                ):
                    print(
                        f"[YOMI-eBPF] [BLOOD RED] KERNEL INTERCEPT: PID {event.pid} spawned suspicious shell: {filename}"
                    )
                    malicious_intent_found = True

        self.bpf_instance["malicious_events"].open_perf_buffer(print_event)  # type: ignore

        start_time = time.time()
        print(
            f"[YOMI-eBPF] [CYBER-PURPLE] Kernel telemetry locked onto PID {target_pid}..."
        )

        while time.time() - start_time < duration_sec:
            try:
                self.bpf_instance.perf_buffer_poll(timeout=100)  # type: ignore
                if malicious_intent_found:
                    break
            except KeyboardInterrupt:
                break

        try:
            del tracked_pids[ctypes.c_uint32(target_pid)]
        except KeyError:
            pass

        return malicious_intent_found


# ==============================================================================
# DEVELOPMENT TESTING BLOCK
# ==============================================================================
if __name__ == "__main__":
    sensor = eBPFSentinel()
    success = sensor.arm_sensor()
    if success:
        test_pid = os.getpid()
        print(f"[+] eBPF initialized. Self-monitoring PID {test_pid} for 10 seconds.")
        print(
            "[+] Test via opening a restricted file: cat /etc/shadow (in another terminal)"
        )
        sensor.monitor_pid(test_pid, duration_sec=10)
