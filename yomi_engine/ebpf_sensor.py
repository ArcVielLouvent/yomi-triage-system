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
# Purpose: Ring-0 Kernel Interception. Injects C code via LLVM BPF Compiler.
#          Migrated to Tracepoints (Stable ABI) for modern Linux v4.17+ support.
#          Uses BPF Hash Maps for zero-overhead, surgically targeted telemetry.
# ==============================================================================


class eBPFSentinel:
    # --------------------------------------------------------------------------
    # SINGLETON PATTERN: Prevents multiple LLVM compilations.
    # --------------------------------------------------------------------------
    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        self.audit = ImmutableStamp()
        self.os_bridge = OSBridge()
        self.bpf_instance = None
        self.is_armed = False

        # ----------------------------------------------------------------------
        # THE KERNEL PAYLOAD (Tracepoint Implementation - Kernel v4.17+ Safe)
        # ----------------------------------------------------------------------
        self.bpf_program = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        // BPF Hash map to store PIDs targeted by the Shadow Net
        BPF_HASH(tracked_pids, u32, u32);

        struct data_t {
            u32 pid;
            u32 event_type; // 1 for openat, 2 for execve
            char comm[16];
            char filename[256];
        };

        BPF_PERF_OUTPUT(malicious_events);

        // [SAFE] Tracepoint implementation for openat (File Access)
        TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            u32 pid = pid_tgid >> 32;

            // FILTER: Only trace PIDs explicitly injected into the map
            u32 *is_tracked = tracked_pids.lookup(&pid);
            if (is_tracked == NULL) {
                return 0; 
            }

            struct data_t data = {};
            data.pid = pid;
            data.event_type = 1;

            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

            malicious_events.perf_submit(args, &data, sizeof(data));
            return 0;
        }

        // [SAFE] Tracepoint implementation for execve (Process Spawning)
        TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
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
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

            malicious_events.perf_submit(args, &data, sizeof(data));
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
                "[YOMI-eBPF]  Compiling Tracepoint payload via LLVM and injecting into Ring-0 Kernel..."
            )
            self.bpf_instance = BPF(text=self.bpf_program)

            self.is_armed = True
            print(
                "[YOMI-eBPF]  eBPF Sentinel Armed via Tracepoints. Waiting for targeted PID injection."
            )
            self.audit.record_action(
                "eBPF",
                "ARMED",
                "Kernel tracepoints (sys_enter_openat, sys_enter_execve) injected globally.",
            )
            return True

        except ImportError:
            print(
                "[YOMI-eBPF] [WARNING] BCC library not found. Kernel syscall tracing unavailable."
            )
            return False
        except Exception as e:
            print(
                f"[YOMI-eBPF] [ERROR] Kernel Injection Failed (Root privileges required): {str(e)}"
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
                        f"[YOMI-eBPF] [BLOOD RED] KERNEL TRACEPOINT INTERCEPT: PID {event.pid} accessed restricted file: {filename}"
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
                        f"[YOMI-eBPF] [BLOOD RED] KERNEL TRACEPOINT INTERCEPT: PID {event.pid} spawned suspicious shell: {filename}"
                    )
                    malicious_intent_found = True

        events_table = self.bpf_instance["malicious_events"]
        events_table.open_perf_buffer(print_event)  # type: ignore

        start_time = time.time()
        print(f"[YOMI-eBPF]  Tracepoint telemetry locked onto PID {target_pid}...")

        while time.time() - start_time < duration_sec:
            try:
                self.bpf_instance.perf_buffer_poll(timeout=100)  # type: ignore
                if malicious_intent_found:
                    break

                # CPU Anti-Spinning protection (Zero-Overhead Enforcement)
                time.sleep(0.01)

            except KeyboardInterrupt:
                break

        # Cleanup: Remove PID from BPF Map to cease surveillance
        try:
            del tracked_pids[ctypes.c_uint32(target_pid)]
        except KeyError:
            pass

        return malicious_intent_found


# ==============================================================================
# PRODUCTION RUNNER (CLI EXECUTION)
# Accepts real PID from the OS. Zero mock/simulation data.
# Usage: sudo python3 ebpf_sensor.py <TARGET_PID>
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[!] Usage: sudo python3 ebpf_sensor.py <TARGET_PID>")
        sys.exit(1)

    try:
        target_pid = int(sys.argv[1])
    except ValueError:
        print("[-] Invalid PID format. Please provide an integer.")
        sys.exit(1)

    if os.geteuid() != 0:
        print(
            "[-] [CRITICAL] eBPF Sentinel requires root privileges. Please run with 'sudo'."
        )
        sys.exit(1)

    if not os.path.exists(f"/proc/{target_pid}"):
        print(f"[-] [ERROR] Target PID {target_pid} does not exist in the system.")
        sys.exit(1)

    sensor = eBPFSentinel()

    print(f"[+] Initializing Ring-0 interception engine...")
    if sensor.arm_sensor():
        detection_status = sensor.monitor_pid(target_pid, duration_sec=30)
        print(
            f"[+] Surveillance ended. Malicious signature match status: {detection_status}"
        )
    else:
        print("[-] Failed to arm eBPF Sentinel.")
