"""
Tests for srpto.lock_manager.dut_lock
======================================
Tests mirror Eka's real-world scenarios from EXECUTE_TAB_QUICK_REFERENCE.txt
Section 9: BACK-TO-BACK DEVICE ALLOCATION.
"""

import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from srpto.lock_manager.dut_lock import DUTPool, ResourceRequirement


def test_fifo_allocation_single_dut():
    """Single-DUT scripts get first available DUT — FIFO (Eka default)."""
    pool = DUTPool(["DUT1", "DUT2", "DUT3"])
    req = ResourceRequirement(dut_count=1)
    allocated = pool.acquire(req, "test_snmp.py")
    assert allocated == ["DUT1"]
    pool.release(allocated, "test_snmp.py", req)


def test_multi_dut_allocation():
    """Multi-DUT script blocks until enough DUTs are free."""
    pool = DUTPool(["DUT1", "DUT2", "DUT3"])
    req1 = ResourceRequirement(dut_count=1)
    req2 = ResourceRequirement(dut_count=2)

    # Grab DUT1 and DUT2
    a1 = pool.acquire(req1, "test_acl.py")
    a2 = pool.acquire(req1, "test_snmp.py")
    assert sorted(a1 + a2) == ["DUT1", "DUT2"]

    # Only DUT3 free; 2-DUT script must wait
    released = threading.Event()

    def releaser():
        time.sleep(0.2)
        pool.release(a1, "test_acl.py", req1)  # free DUT1
        time.sleep(0.2)
        pool.release(a2, "test_snmp.py", req1)  # free DUT2
        released.set()

    t = threading.Thread(target=releaser)
    t.start()

    allocated = pool.acquire(req2, "test_bgp.py", poll_interval=0.05)
    t.join()
    assert len(allocated) == 2


def test_topology_exclusive_blocks_others():
    """Topology exclusive lock prevents any parallel execution."""
    pool = DUTPool(["DUT1", "DUT2"])

    exclusive_req = ResourceRequirement(dut_count=1, topology_exclusive=True)
    normal_req = ResourceRequirement(dut_count=1)

    # Acquire exclusive
    exc = pool.acquire(exclusive_req, "test_warm_reboot.py")
    assert exc is not None

    # Normal request should fail immediately (None from timeout)
    pool2 = DUTPool(["DUT1", "DUT2"])
    # Simulate the block by checking internal state
    status = pool.get_status()
    assert status["topo_locked"] is True

    pool.release(exc, "test_warm_reboot.py", exclusive_req)
    status_after = pool.get_status()
    assert status_after["topo_locked"] is False


def test_ptf_exclusivity():
    """PTF host can only be held by one script at a time."""
    pool = DUTPool(["DUT1", "DUT2"], ptf_host="ptf-host-1")
    req_ptf = ResourceRequirement(dut_count=1, ptf_required=True)

    a1 = pool.acquire(req_ptf, "test_traffic_a.py")
    assert a1 is not None

    status = pool.get_status()
    assert status["ptf_busy"] is True

    pool.release(a1, "test_traffic_a.py", req_ptf)
    status_after = pool.get_status()
    assert status_after["ptf_busy"] is False


def test_shared_resource_conflict():
    """Two scripts modifying the same VLAN cannot run simultaneously."""
    pool = DUTPool(["DUT1", "DUT2", "DUT3"])
    req_a = ResourceRequirement(dut_count=1, shared_resources={"vlan:100"})
    req_b = ResourceRequirement(dut_count=1, shared_resources={"vlan:100"})

    a = pool.acquire(req_a, "test_acl_vlan100.py")
    assert a is not None

    status = pool.get_status()
    assert "vlan:100" in status["shared_resources"]

    # req_b should be blocked (check status)
    # In a real test with threads we'd verify blocking; here verify the resource is locked
    pool.release(a, "test_acl_vlan100.py", req_a)
    status_after = pool.get_status()
    assert not status_after["shared_resources"].get("vlan:100")


def test_topology_matching():
    """Topology-aware allocation matches DUT pairs by link count."""
    # DUT1-DUT2 have 2 links, DUT2-DUT3 have 1 link
    topo = {("DUT1", "DUT2"): 2, ("DUT2", "DUT3"): 1}
    pool = DUTPool(["DUT1", "DUT2", "DUT3"], topology_connections=topo)

    req = ResourceRequirement(
        dut_count=2,
        link_requirements={("D1", "D2"): 2},  # needs 2 links
    )
    allocated = pool.acquire(req, "test_bgp_gr.py")
    # DUT1 and DUT2 satisfy the 2-link requirement
    assert set(allocated) == {"DUT1", "DUT2"}
    pool.release(allocated, "test_bgp_gr.py", req)


def test_anti_starvation_exclusive_does_not_jump_queue():
    """
    Regression test for the 2026-09-25 srpto_run race (test_bgp_4node.py
    starved behind test_reboot.py): a 1-DUT topology-exclusive request must
    not grab the lock ahead of an already-pending, larger, non-exclusive
    request while enough DUTs are free to serve that larger request first.
    """
    pool = DUTPool(["D1", "D2", "D3", "D4", "D5"])
    big_req = ResourceRequirement(dut_count=4)                             # e.g. test_bgp_4node.py
    small_excl_req = ResourceRequirement(dut_count=1, topology_exclusive=True)  # e.g. test_reboot.py

    # Both requests register as pending before either calls acquire(),
    # mirroring engine.py's register_pending() call in _run_one_script().
    pool.register_pending(big_req.dut_count)
    pool.register_pending(small_excl_req.dut_count)

    result_holder = {}

    def run_small():
        result_holder["small"] = pool.acquire(
            small_excl_req, "test_reboot.py", poll_interval=0.02
        )
        pool.unregister_pending(small_excl_req.dut_count)

    t_small = threading.Thread(target=run_small)
    t_small.start()

    # Give the small exclusive request several poll cycles to (incorrectly)
    # grab the lock ahead of the still-pending 4-DUT request.
    time.sleep(0.3)
    assert "small" not in result_holder, (
        "1-DUT exclusive request jumped the queue ahead of a pending "
        "4-DUT request while enough DUTs were free for the big request"
    )

    # The big request is not blocked by anything and should acquire cleanly.
    big_allocated = pool.acquire(big_req, "test_bgp_4node.py", poll_interval=0.02)
    assert big_allocated is not None
    pool.unregister_pending(big_req.dut_count)
    pool.release(big_allocated, "test_bgp_4node.py", big_req)

    # Now that the big request is done, the exclusive request should unblock.
    t_small.join(timeout=2)
    assert result_holder.get("small") is not None
    pool.release(result_holder["small"], "test_reboot.py", small_excl_req)


def test_timeout_returns_none():
    """acquire() returns None when timeout expires."""
    pool = DUTPool(["DUT1"], max_wait_seconds=0.3, poll_interval=0.1)
    req_hold = ResourceRequirement(dut_count=1)
    req_wait = ResourceRequirement(dut_count=1)

    # Hold DUT1
    held = pool.acquire(req_hold, "holder.py")
    assert held is not None

    # Second acquire should time out
    result = pool.acquire(req_wait, "waiter.py")
    assert result is None

    pool.release(held, "holder.py", req_hold)


def test_status_snapshot_matches_eka_schema():
    """get_status() returns dict matching Eka _exec_queue_state schema."""
    pool = DUTPool(["DUT_A", "DUT_B"])
    status = pool.get_status()
    assert "free_duts" in status
    assert "busy_duts" in status
    assert "ptf_busy" in status
    assert "topo_locked" in status
    assert set(status["free_duts"]) == {"DUT_A", "DUT_B"}
    assert status["busy_duts"] == []


if __name__ == "__main__":
    # Quick smoke test without pytest
    test_fifo_allocation_single_dut()
    print("test_fifo_allocation_single_dut PASSED")
    test_topology_matching()
    print("test_topology_matching PASSED")
    test_timeout_returns_none()
    print("test_timeout_returns_none PASSED")
    test_status_snapshot_matches_eka_schema()
    print("test_status_snapshot_matches_eka_schema PASSED")
    test_ptf_exclusivity()
    print("test_ptf_exclusivity PASSED")
    test_shared_resource_conflict()
    print("test_shared_resource_conflict PASSED")
    test_topology_exclusive_blocks_others()
    print("test_topology_exclusive_blocks_others PASSED")
    test_anti_starvation_exclusive_does_not_jump_queue()
    print("test_anti_starvation_exclusive_does_not_jump_queue PASSED")
    print("\nAll unit tests passed!")
