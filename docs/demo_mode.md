# Demo Mode

By default, Yomi's invasive-tier modules (Shadow Net, Sandbox, Mirage, Ghost
Protocol, raw eBPF Sensor) are **disabled**. This is the safe default for
unattended / enterprise deployment -- see `yomi_core/module_registry.py` for
the full rationale per module.

For live demos where you want the complete feature surface visible, source
the demo profile before launch:

```bash
export YOMI_MODULE_SHADOW_NET=true
export YOMI_MODULE_SANDBOX=true
export YOMI_MODULE_MIRAGE=true
export YOMI_MODULE_GHOST=true
export YOMI_MODULE_EBPF_SENSOR=true

sudo -E python3 yomi_core/cli.py --auto
```

Or programmatically via `yomi_core.module_registry.DEMO_PROFILE_ENV`.

This file (and the registry it documents) is the enforcement mechanism for
one hard rule going forward: **every module in this codebase must be
reachable and toggleable from one central place.** No module is allowed to
exist in the source tree without an entry in `module_registry.py` and a
decision -- default on, default off, or explicitly deprecated/removed.
