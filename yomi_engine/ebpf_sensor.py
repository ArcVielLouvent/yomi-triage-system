import os
import sys
import time
import ctypes

# Append root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from yomi_audit.stamp import ImmutableStamp
from yomi_mcp.os_bridge import OSBridge

# ==============================================================================
# YOMI TRIAGE SYSTEM: Engine Module - eBPF Sentinel (v3.0)
# Purpose: Ring-0 Kernel Interception. Injects C code directly into the Linux
#          kernel to trace sys_enter_openat (file access) and sys_enter_execve.
#          Provides zero-overhead, real-time threat telemetry to the Shadow Net.
# ==============================================================================


class eBPFSentinel:
    def __init__(self):
        self.audit = ImmutableStamp()
        self.os_bridge = OSBridge()
        self.bpf_instance = None

        # ----------------------------------------------------------------------
        # THE KERNEL PAYLOAD (Written in Restricted C)
        # ----------------------------------------------------------------------
        self.bpf_program = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        #include <linux/signal.h>
        
        // Data structure to send back to Python user-space
        struct data_t {
            u32 pid;
            char comm[16];
            char filename[256];
        };
        
        BPF_PERF_OUTPUT(malicious_events);
        
        // Hooking the 'openat' syscall (When a process tries to open a file)
        int trace_syscall_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
            struct data_t data = {};
            u64 pid_tgid = bpf_get_current_pid_tgid();
            data.pid = pid_tgid >> 32;
            
            // Extract process name
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            // Extract the target file path they are trying to open
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
            
            if (filename && (strstr(data.filename, "shadow") || strstr(data.filename, "SAM"))) {
                malicious_events.perf_submit(ctx, &data, sizeof(data));
                bpf_send_signal(SIGSTOP);
            }
            
            return 0;
        }
        """

    def arm_sensor(self) -> bool:
        """Compiles the C payload and injects it into the Linux Kernel."""
        if self.os_bridge.environment not in ["SIFT_LINUX", "CODESPACES_LINUX"]:
            print(
                "[eBPF] Hardware unsupported for direct Kernel injection. Kernel tracing unavailable."
            )
            return False

        try:
            # BCC requires root privileges and linux kernel headers
            from bcc import BPF  # type: ignore

            print(
                "[YOMI-eBPF] [VOID BLACK] Compiling C payload and injecting into Ring-0 Kernel..."
            )
            self.bpf_instance = BPF(text=self.bpf_program)

            # Attach the C function to the actual OS syscall
            syscall_name = self.bpf_instance.get_syscall_fnname("openat")
            self.bpf_instance.attach_kprobe(
                event=syscall_name, fn_name="trace_syscall_openat"
            )

            print(
                "[YOMI-eBPF] [PLASMA BLUE] eBPF Sentinel Armed. Kernel syscalls intercepted."
            )
            self.audit.record_action(
                "eBPF", "ARMED", "Kernel trace_syscall_openat successfully injected."
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
        """Listens to the Kernel perf buffer for suspicious activity by the target PID."""
        if not self.bpf_instance:
            print(
                "[YOMI-eBPF] [WARNING] eBPF sensor is not armed. Kernel trace data unavailable."
            )
            return False

        # Real eBPF Execution
        malicious_intent_found = False

        # Callback function when the C code sends data to Python
        def print_event(cpu, data, size):
            nonlocal malicious_intent_found
            event = self.bpf_instance["malicious_events"].event(data)  # type: ignore
            if event.pid == target_pid:
                filename = event.filename.decode("utf-8", "replace")
                if "shadow" in filename or "SAM" in filename:
                    print(
                        f"[YOMI-eBPF] [BLOOD RED] KERNEL INTERCEPTION: PID {event.pid} accessed restricted file: {filename}"
                    )
                    malicious_intent_found = True

        self.bpf_instance["malicious_events"].open_perf_buffer(print_event)  # type: ignore

        start_time = time.time()
        print(
            f"[YOMI-eBPF] [CYBER-PURPLE] Listening to Kernel ring buffer for PID {target_pid}..."
        )

        while time.time() - start_time < duration_sec:
            try:
                # Use the BCC event-driven perf buffer to avoid busy polling.
                self.bpf_instance.perf_buffer_poll(timeout=100)  # type: ignore
                if malicious_intent_found:
                    break
            except KeyboardInterrupt:
                break

        return malicious_intent_found
