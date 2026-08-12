# Unit Tests

One file per module, mirroring the source tree:
- test_stamp.py           -> yomi_audit/stamp.py
- test_os_bridge.py       -> yomi_mcp/os_bridge.py
- test_yomi_data.py       -> yomi_data/__init__.py
- test_sift_toolkit.py    -> yomi_mcp/sift_toolkit.py
- test_harness.py         -> yomi_mcp/harness.py
- ... etc, one per module across all five packages.

Rule: a unit test may only import the module under test + its already-verified
lower-layer dependencies. It must NOT spin up real subprocesses against real
SIFT binaries, real eBPF, or real network/LLM calls -- those go in integration/.
Mock at the subprocess/network boundary.
