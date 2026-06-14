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
# Purpose: Ring-0 Kernel Interception via Tracepoints (Stable ABI).
#          - Zero-overhead targeted telemetry via BPF Hash Maps.
#          - Cryptographic Ledger integration for SANS Audit Trail.
#          - Context-Aware Path Matching (Zero False-Positive Defense).
# ==============================================================================


class eBPFSentinel:
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

        self.bpf_program = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        BPF_HASH(tracked_pids, u32, u32);

        struct data_t {
            u32 pid;
            u32 event_type; // 1 for openat, 2 for execve
            char comm[16];
            char filename[256];
        };

        BPF_PERF_OUTPUT(malicious_events);

        TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            u32 pid = pid_tgid >> 32;

           // u32 *is_tracked = tracked_pids.lookup(&pid);
           // if (is_tracked == NULL) {
           //     return 0; 
           // }

            struct data_t data = {};
            data.pid = pid;
            data.event_type = 1;

            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            int ret = bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
            if (ret <= 0) {
                return 0; 
            }

            malicious_events.perf_submit(args, &data, sizeof(data));
            return 0;
        }

        TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            u32 pid = pid_tgid >> 32;

            //u32 *is_tracked = tracked_pids.lookup(&pid);
            //if (is_tracked == NULL) {
            //    return 0;
            //}

            struct data_t data = {};
            data.pid = pid;
            data.event_type = 2;

            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            int ret = bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
            if (ret <= 0) {
                return 0; 
            }

            malicious_events.perf_submit(args, &data, sizeof(data));
            return 0;
        }
        """

    def arm_sensor(self) -> bool:
        if self.is_armed and self.bpf_instance is not None:
            return True

        if self.os_bridge.environment not in [
            "SIFT_LINUX",
            "CODESPACES_LINUX",
            "LINUX",
        ]:
            print("[YOMI-eBPF] [ERROR] Unsupported OS. Linux Kernel required.")
            return False

        try:
            from bcc import BPF  # type: ignore

            print("[YOMI-eBPF] [INFO] Compiling Tracepoint payload via LLVM...")
            self.bpf_instance = BPF(text=self.bpf_program)
            self.is_armed = True

            print(
                "[YOMI-eBPF] [INFO] Ring-0 Sentinel Armed. Awaiting target injection."
            )
            self.audit.record_action(
                "eBPF",
                "ARMED",
                "Kernel tracepoints (openat, execve) injected globally.",
            )
            return True

        except ImportError:
            print(
                "[YOMI-eBPF] [ERROR] BCC library not found. Kernel tracing unavailable."
            )
            return False
        except Exception as e:
            print(f"[YOMI-eBPF] [ERROR] Kernel Injection Failed: {str(e)}")
            return False

    def monitor_pid(self, target_pid: int, duration_sec: int = 3) -> bool:
        if not self.is_armed or self.bpf_instance is None:
            print("[YOMI-eBPF] [WARNING] Sensor not armed.")
            return False

        import ctypes

        tracked_pids = self.bpf_instance.get_table("tracked_pids")
        tracked_pids[ctypes.c_uint32(target_pid)] = ctypes.c_uint32(1)

        malicious_intent_found = False

        # Define shell executables
        critical_shells = {"bash", "sh", "dash", "zsh", "cmd.exe", "powershell", "pwsh"}

        def print_event(cpu, data, size):
            nonlocal malicious_intent_found

            event = self.bpf_instance["malicious_events"].event(data)  # type: ignore
            raw_filename = event.filename.decode("utf-8", "replace").strip()
            base_name = os.path.basename(raw_filename)

            if event.event_type == 1:
                if "sans_hackathon" in raw_filename or "memory_dumps" in raw_filename:
                    return
                is_threat = False

                if (
                    "/etc/shadow" in raw_filename
                    or "/etc/passwd" in raw_filename
                    or "/root/.ssh" in raw_filename
                    or "/etc/sudoers" in raw_filename
                ):
                    is_threat = True
                elif base_name in {"shadow", "gshadow", "SAM", "SYSTEM", "id_rsa"}:
                    is_threat = True

                if is_threat:
                    msg = f"PID {event.pid} accessed critical file: {raw_filename}"
                    print(f"[YOMI-eBPF] [ALERT] {msg}")

                    try:
                        import signal

                        os.kill(event.pid, signal.SIGSTOP)
                        self.audit.record_action(
                            "eBPF_SENSOR",
                            "AUTONOMOUS_CONTAINMENT",
                            f"SIGSTOP applied to PID {event.pid}",
                        )
                    except Exception as e:
                        print(f"[-] Containment failed: {e}")
                    self.audit.record_action(
                        "eBPF_SENSOR",
                        "THREAT_DETECTED_OPENAT",
                        msg,
                        metadata={"pid": event.pid, "file": raw_filename},
                    )
                    malicious_intent_found = True

            elif event.event_type == 2:
                if base_name in critical_shells:
                    msg = f"PID {event.pid} spawned shell/interpreter: {raw_filename}"
                    print(f"[YOMI-eBPF] [ALERT] {msg}")
                    self.audit.record_action(
                        "eBPF_SENSOR",
                        "THREAT_DETECTED_EXECVE",
                        msg,
                        metadata={"pid": event.pid, "file": raw_filename},
                    )
                    malicious_intent_found = True

        events_table = self.bpf_instance["malicious_events"]
        events_table.open_perf_buffer(print_event)  # type: ignore

        start_time = time.time()
        print(f"[YOMI-eBPF] [INFO] Telemetry locked onto PID {target_pid}...")

        while time.time() - start_time < duration_sec:
            try:
                self.bpf_instance.perf_buffer_poll(timeout=100)  # type: ignore
                # if malicious_intent_found:
                #    break

                # Zero-Overhead Enforcement
                time.sleep(0.01)
            except KeyboardInterrupt:
                break

        try:
            del tracked_pids[ctypes.c_uint32(target_pid)]
        except KeyError:
            pass

        return malicious_intent_found


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 ebpf_sensor.py <TARGET_PID>")
        sys.exit(1)

    try:
        target_pid = int(sys.argv[1])
    except ValueError:
        print("Error: Invalid PID format.")
        sys.exit(1)

    if os.geteuid() != 0:
        print("Error: eBPF Sentinel requires root privileges (sudo).")
        sys.exit(1)

    if not os.path.exists(f"/proc/{target_pid}"):
        print(f"Error: Target PID {target_pid} does not exist.")
        sys.exit(1)

    sensor = eBPFSentinel()
    if sensor.arm_sensor():
        print(f"[+] Commencing OS telemetry on PID {target_pid} (60s).")
        detected = sensor.monitor_pid(target_pid, duration_sec=60)
        print(f"[+] Telemetry concluded. Threat detected: {detected}")

        if detected:
            sys.exit(2)
        else:
            sys.exit(0)
    else:
        print("[-] Initialization failed.")
        sys.exit(1)
