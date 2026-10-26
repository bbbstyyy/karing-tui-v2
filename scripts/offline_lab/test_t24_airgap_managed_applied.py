#!/usr/bin/env python3
"""Fast fail-closed ADR 0149 policy tests; no Core/Docker/remote sockets."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

import t24_airgap_managed_applied as applied
import t24_airgap_loopback_core as loopback


class AppliedManagedPolicyTests(unittest.TestCase):
    def status(self, desired="stopped", running=False):
        return {
            "api_version": "v1", "core_configured": True,
            "core_desired_state": desired,
            "core_state": "running" if running else "stopped",
            "core_pid": 123 if running else 0,
            "core_circuit_open": False, "recovery_required": False,
            "config_revision": 1, "declaration_revision": 1,
            "applied_generation_id": 5,
        }

    def test_synthetic_v1_document_never_imports_cn_or_remote_endpoints(self):
        doc = applied.local_document(39871)
        applied.assert_synthetic_document(doc, 39871)
        serialized = json.dumps(doc, sort_keys=True)
        for forbidden in ("rule_sets", "region_append", "cn_preset",
                          "https://", "tun", "8.8.8.8", "example.com"):
            self.assertNotIn(forbidden, serialized)

    def test_mutated_declaration_must_fail_safe(self):
        source = applied.local_document(39871)
        modifications = (
            ("remote-node", lambda d: d["nodes"][0].update({"server": "8.8.8.8"})),
            ("public-node", lambda d: d["nodes"][0].update({"server": "0.0.0.0"})),
            ("selected-fallback", lambda d: d["selection"]["current"].update(
                {"default": {"kind": "direct"}})),
            ("foreign-port", lambda d: d["nodes"][0].update({"port": 4444})),
            ("rule-set", lambda d: d.update({"rule_sets": [
                {"ref": "geosite:cn", "sha256": "0" * 64, "format": "source"}]})),
            ("region", lambda d: d["routing"].update(
                {"region_append": {"region_code": "cn"}})),
            ("non-direct-final", lambda d: d["routing"].update(
                {"final": {"kind": "block"}})),
            ("remote-dns", lambda d: d["dns"]["profiles"][0].update(
                {"server": "1.1.1.1"})),
            ("tun", lambda d: d.update({"tun": True})),
        )
        for name, mutation in modifications:
            with self.subTest(name=name):
                altered = json.loads(json.dumps(source))
                mutation(altered)
                with self.assertRaises(RuntimeError):
                    applied.assert_synthetic_document(altered, 39871)

    def test_committed_status_must_bind_generation_and_run_intent(self):
        self.assertEqual(
            applied.committed_snapshot(self.status(), 5, "stopped", False), 0)
        self.assertEqual(
            applied.committed_snapshot(self.status("running", True), 5,
                                       "running", True), 123)
        changes = (
            ("config_revision", 2), ("declaration_revision", 2),
            ("applied_generation_id", None), ("last_known_good_generation_id", None),
            ("core_desired_state", "running"), ("core_state", "running"),
            ("core_pid", 999), ("recovery_required", True),
            ("core_circuit_open", True), ("core_configured", False),
        )
        for field, value in changes:
            with self.subTest(field=field):
                changed = self.status()
                changed[field] = value
                if field == "last_known_good_generation_id":
                    # An optional prior LKG ID is permitted and is not a
                    # replacement for the actual applied generation.
                    continue
                with self.assertRaises(RuntimeError):
                    applied.committed_snapshot(changed, 5, "stopped", False)

    def test_staged_revision_changes_only_logging_and_refuses_network_mutation(self):
        base = applied.local_document(39871)
        staged = applied.staged_document(base, 39871)
        applied.assert_staged_document(staged, 39871)
        self.assertEqual(base["log_level"], "warn")
        self.assertEqual(staged["log_level"], "error")
        original = dict(staged)
        for name, mutate in (
            ("remote-node", lambda d: d["nodes"][0].update({"server": "8.8.8.8"})),
            ("new-rules", lambda d: d.update({"rule_sets": ["geoip:cn"]})),
            ("route-bypass", lambda d: d["routing"].update({"final": {"kind": "block"}})),
            ("remote-dns", lambda d: d["dns"]["profiles"][0].update({"server": "1.1.1.1"})),
            ("privileged-inbound", lambda d: d.update({"tun": True})),
            ("unapproved-level", lambda d: d.update({"log_level": "debug"})),
        ):
            with self.subTest(name=name):
                altered = json.loads(json.dumps(staged))
                mutate(altered)
                with self.assertRaises(RuntimeError):
                    applied.assert_staged_document(altered, 39871)
        self.assertEqual(staged, original)

    def test_unapplied_revision_retains_original_core_pid_and_lkg(self):
        status = self.status("running", True)
        status.update({
            "declaration_revision": 2,
            "last_known_good_generation_id": 5,
            "active_operation": "",
        })
        applied.assert_unapplied_core_unchanged(status, 5, 123, 2)
        for name, bad in (
            ("config revision", {"config_revision": 2}),
            ("applied generation", {"applied_generation_id": 9}),
            ("LKG drift", {"last_known_good_generation_id": 10}),
            ("PID churn", {"core_pid": 124}),
            ("running intent", {"core_desired_state": "stopped"}),
            ("declaration revision", {"declaration_revision": 1}),
            ("recovery", {"recovery_required": True}),
            ("busy apply", {"active_operation": "config-apply"}),
        ):
            with self.subTest(name=name):
                changed = dict(status)
                changed.update(bad)
                with self.assertRaises(RuntimeError):
                    applied.assert_unapplied_core_unchanged(changed, 5, 123, 2)
        with self.assertRaises(RuntimeError):
            applied.assert_unapplied_core_unchanged(status, 5, 123, 3)

    def test_unapplied_stage_rejects_invalid_candidate_and_stale_apply(self):
        original_doc = applied.local_document(39871)
        original_sha, staged_sha = "a" * 64, "b" * 64
        original_config, staged_config = "c" * 64, "d" * 64
        head = {"revision": 1, "sha256": original_sha, "document": original_doc}
        calls = []
        probes = []

        class Node:
            calls = 0
            failed = False
        node = Node()

        def fake_api(_sock, method, route, payload=None, expected=200,
                     timeout=85):
            calls.append((method, route, expected))
            if (method, route) == ("GET", "/v1/declaration/current"):
                return dict(head)
            if (method, route) == ("GET", "/v1/status"):
                status = self.status("running", True)
                status.update({
                    "declaration_revision": head["revision"],
                    "last_known_good_generation_id": 5,
                    "active_operation": "",
                })
                return status
            if (method, route) == ("POST", "/v1/declaration"):
                self.assertEqual(payload["expected_revision"], 1)
                if payload["document"].get("tun"):
                    self.assertEqual(expected, 400)
                    return {"error": "unknown field"}
                self.assertEqual(expected, 201)
                applied.assert_staged_document(payload["document"], 39871)
                head.update({"revision": 2, "sha256": staged_sha,
                             "document": payload["document"]})
                return {"revision": 2, "sha256": staged_sha}
            if (method, route) == ("POST", "/v1/declaration/compile"):
                self.assertEqual(payload, {"revision": 2})
                return {
                    "revision": 2, "declaration_sha256": staged_sha,
                    "config_sha256": staged_config, "rule_set_count": 0,
                }
            if (method, route) == ("POST", "/v1/declaration/apply"):
                self.assertEqual(payload, {
                    "declaration_revision": 2,
                    "expected_config_revision": 0,
                })
                self.assertEqual(expected, 409)
                return {"error": "stale config revision"}
            raise AssertionError("unapproved API request")

        def probe(echo_port, payload_prefix, target):
            self.assertEqual((echo_port, target), (41001, node))
            probes.append(payload_prefix)

        with mock.patch.object(applied, "unix_json", side_effect=fake_api):
            with mock.patch.object(applied, "probe_isolated_routes",
                                   side_effect=probe):
                sha = applied.stage_and_reject_stale_apply(
                    "/test.sock", 5, 123, original_doc, 39871,
                    original_sha, original_config, 41001, node)
        self.assertEqual(sha, (staged_sha, staged_config))
        self.assertEqual(original_doc["log_level"], "warn")
        self.assertEqual(probes, [b"staged-not-applied-"])
        self.assertEqual(calls.count(("GET", "/v1/declaration/current", 200)), 3)
        self.assertIn(("POST", "/v1/declaration", 400), calls)
        self.assertIn(("POST", "/v1/declaration/apply", 409), calls)

    def test_stale_apply_must_report_refusal_not_success(self):
        source = applied.local_document(39871)
        original_sha, staged_sha = "a" * 64, "b" * 64
        state = {"revision": 1, "sha256": original_sha, "document": source}

        def fake_api(_sock, method, route, payload=None, expected=200,
                     timeout=85):
            if route == "/v1/declaration/current":
                return dict(state)
            if route == "/v1/status":
                status = self.status("running", True)
                status.update({
                    "declaration_revision": state["revision"],
                    "last_known_good_generation_id": 5,
                    "active_operation": "",
                })
                return status
            if route == "/v1/declaration":
                if expected == 400:
                    return {"error": "rejected"}
                state.update({
                    "revision": 2, "sha256": staged_sha,
                    "document": payload["document"],
                })
                return {"revision": 2, "sha256": staged_sha}
            if route == "/v1/declaration/compile":
                return {
                    "revision": 2, "declaration_sha256": staged_sha,
                    "config_sha256": "d" * 64, "rule_set_count": 0,
                }
            if route == "/v1/declaration/apply":
                return {}  # A missing typed conflict must never pass.
            raise AssertionError("unexpected request")

        with mock.patch.object(applied, "unix_json", side_effect=fake_api):
            with self.assertRaises(RuntimeError):
                applied.stage_and_reject_stale_apply(
                    "/test.sock", 5, 123, source, 39871,
                    original_sha, "c" * 64, 41001, object())

    def test_promoted_status_requires_new_generation_lkg_and_running_pid(self):
        running = self.status("running", True)
        running.update({
            "config_revision": 2, "declaration_revision": 2,
            "applied_generation_id": 9, "last_known_good_generation_id": 9,
            "core_pid": 222, "active_operation": "",
        })
        self.assertEqual(applied.assert_promoted_core(
            running, 5, 9, 123, True), 222)
        self.assertEqual(applied.assert_promoted_core(
            running, 5, 9, None, True), 222)
        stopped = dict(running)
        stopped.update({"core_state": "stopped", "core_desired_state": "stopped",
                        "core_pid": 0})
        self.assertEqual(applied.assert_promoted_core(
            stopped, 5, 9, None, False), 0)
        for name, change in (
            ("old applied revision", {"config_revision": 1}),
            ("old declaration", {"declaration_revision": 1}),
            ("old generation", {"applied_generation_id": 5}),
            ("wrong last-known-good", {"last_known_good_generation_id": 5}),
            ("core not running", {"core_state": "stopped"}),
            ("running intent absent", {"core_desired_state": "stopped"}),
            ("old core PID", {"core_pid": 123}),
            ("recovery demanded", {"recovery_required": True}),
            ("apply still pending", {"active_operation": "declaration-apply"}),
            ("circuit open", {"core_circuit_open": True}),
        ):
            with self.subTest(name=name):
                changed = dict(running)
                changed.update(change)
                with self.assertRaises(RuntimeError):
                    applied.assert_promoted_core(changed, 5, 9, 123, True)
        for old_generation in (0, 9, 10):
            with self.subTest(generation=old_generation):
                with self.assertRaises(RuntimeError):
                    applied.assert_promoted_core(
                        running, old_generation, 9, 123, True)

    def test_valid_cas_promotes_staged_generation_and_checks_local_traffic(self):
        stage_sha, config_sha = "b" * 64, "d" * 64
        state = {"applied": False}
        operations = []
        class Node:
            pass
        node = Node()

        def status():
            result = self.status("running", True)
            result.update({"declaration_revision": 2,
                           "last_known_good_generation_id": 5,
                           "active_operation": ""})
            if state["applied"]:
                result.update({
                    "config_revision": 2,
                    "applied_generation_id": 9,
                    "last_known_good_generation_id": 9,
                    "core_pid": 222,
                })
            return result

        def fake_api(sock, method, route, payload=None, expected=200,
                     timeout=85):
            self.assertEqual(sock, "/test.sock")
            operations.append((method, route))
            if route == "/v1/status":
                return status()
            if route == "/v1/declaration/current":
                return {"revision": 2, "sha256": stage_sha}
            if route == "/v1/declaration/compile":
                self.assertEqual(payload, {"revision": 2})
                return {"revision": 2, "declaration_sha256": stage_sha,
                        "config_sha256": config_sha, "rule_set_count": 0}
            if route == "/v1/declaration/apply":
                self.assertEqual(payload, {
                    "declaration_revision": 2, "expected_config_revision": 1,
                })
                self.assertEqual(expected, 200)
                state["applied"] = True
                return {
                    "generation_id": 9, "attempt_id": 17,
                    "base_config_revision": 1, "target_config_revision": 2,
                    "declaration_revision": 2,
                    "declaration_sha256": stage_sha,
                    "config_sha256": config_sha,
                }
            raise AssertionError("unexpected privileged management route")

        with mock.patch.object(applied, "unix_json", side_effect=fake_api):
            with mock.patch.object(applied, "wait_status", side_effect=(
                lambda *_args: status())):
                with mock.patch.object(applied, "verify_child") as child:
                    with mock.patch.object(applied, "probe_isolated_routes") as probe:
                        promoted = applied.promote_staged_generation(
                            "/test.sock", "/app", {}, 100, "/approved-core",
                            5, 123, stage_sha, config_sha, 41001, node)
        self.assertEqual(promoted, (9, 222))
        child.assert_called_once_with(222, 100, "/approved-core")
        probe.assert_called_once_with(41001, b"promoted-live-", node)
        self.assertEqual(operations.count(("POST", "/v1/declaration/apply")), 1)
        self.assertFalse(any(route == "/v1/declaration" for _, route in operations))

    def test_unsafe_handoff_receipts_fail_before_any_health_probe(self):
        stage_sha, config_sha = "b" * 64, "d" * 64
        good_receipt = {
            "generation_id": 9, "attempt_id": 17,
            "base_config_revision": 1, "target_config_revision": 2,
            "declaration_revision": 2,
            "declaration_sha256": stage_sha, "config_sha256": config_sha,
        }
        for field, value in (
            ("generation_id", 5),
            ("generation_id", True),
            ("attempt_id", 0),
            ("base_config_revision", 0),
            ("target_config_revision", 1),
            ("declaration_revision", 1),
            ("declaration_sha256", "a" * 64),
            ("config_sha256", "c" * 64),
        ):
            with self.subTest(field=field, value=value):
                state = self.status("running", True)
                state.update({"declaration_revision": 2,
                              "last_known_good_generation_id": 5,
                              "active_operation": ""})
                receipt = dict(good_receipt)
                receipt[field] = value

                def fake_api(_sock, _method, route, payload=None,
                             expected=200, timeout=85):
                    if route == "/v1/status":
                        return dict(state)
                    if route == "/v1/declaration/current":
                        return {"revision": 2, "sha256": stage_sha}
                    if route == "/v1/declaration/compile":
                        return {"revision": 2, "declaration_sha256": stage_sha,
                                "config_sha256": config_sha, "rule_set_count": 0}
                    if route == "/v1/declaration/apply":
                        return dict(receipt)
                    raise AssertionError("unexpected management route")

                with mock.patch.object(applied, "unix_json", side_effect=fake_api):
                    with mock.patch.object(applied, "wait_status") as wait:
                        with self.assertRaises(RuntimeError):
                            applied.promote_staged_generation(
                                "/test.sock", "/app", {}, 100, "/approved-core",
                                5, 123, stage_sha, config_sha, 41001, object())
                        wait.assert_not_called()

    def promoted_status(self, pid=222, failures=0):
        status = self.status("running", True)
        status.update({
            "config_revision": 2, "declaration_revision": 2,
            "applied_generation_id": 9, "last_known_good_generation_id": 9,
            "core_pid": pid, "active_operation": "",
            "core_consecutive_failures": failures,
        })
        return status

    def test_crash_watch_rejects_old_pid_and_requires_supervised_new_child(self):
        backoff = self.promoted_status(pid=0)
        backoff["core_state"] = "backoff"
        old_running = self.promoted_status(pid=222)
        recovered = self.promoted_status(pid=333, failures=1)
        with mock.patch.object(applied, "unix_json",
                               side_effect=[backoff, old_running, recovered]) as api:
            with mock.patch.object(applied.time, "sleep") as sleep:
                self.assertEqual(
                    applied.wait_restarted_promoted_core(
                        "/daemon.sock", 5, 9, 222, timeout=5), 333)
        self.assertEqual(api.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

        for field, change in (
            ("same-pid", {"core_pid": 222}),
            ("unrecorded-failure", {"core_consecutive_failures": 0}),
            ("old-declaration", {"declaration_revision": 1}),
            ("old-config", {"config_revision": 1}),
            ("wrong-LKG", {"last_known_good_generation_id": 5}),
            ("wrong-applied", {"applied_generation_id": 5}),
            ("operator-stopped", {"core_desired_state": "stopped"}),
            ("recovery-required", {"recovery_required": True}),
            ("circuit-open", {"core_circuit_open": True}),
        ):
            with self.subTest(field=field):
                bad = dict(recovered)
                bad.update(change)
                with mock.patch.object(applied, "unix_json", return_value=bad):
                    with mock.patch.object(applied.time, "monotonic",
                                           side_effect=[0, 0, 99]):
                        with mock.patch.object(applied.time, "sleep"):
                            with self.assertRaises(RuntimeError):
                                applied.wait_restarted_promoted_core(
                                    "/daemon.sock", 5, 9, 222, timeout=1)

        with mock.patch.object(applied.time, "monotonic",
                               side_effect=[0, 2]):
            with self.assertRaises(RuntimeError):
                applied.wait_restarted_promoted_core(
                    "/daemon.sock", 5, 9, 222, timeout=1)
        for invalid in (0, -1, 33.0, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RuntimeError):
                    applied.wait_restarted_promoted_core(
                        "/daemon.sock", 5, 9, invalid, timeout=3)

    def test_pidfd_crash_injection_is_bound_to_owned_core(self):
        first = self.promoted_status(pid=222)
        recovered = self.promoted_status(pid=333, failures=1)
        events = []
        class Node:
            pass
        node = Node()

        def verify(pid, daemon, path):
            events.append(("verify", pid, daemon, path))
        def signal_pidfd(fd, sig):
            events.append(("signal", fd, sig))

        with mock.patch.object(applied, "unix_json",
                               side_effect=[first, first, recovered, recovered]):
            with mock.patch.object(applied.os, "pidfd_open", return_value=71) as opened:
                with mock.patch.object(applied.signal, "pidfd_send_signal",
                                       side_effect=signal_pidfd) as sent:
                    with mock.patch.object(applied.os, "close") as closed:
                        with mock.patch.object(applied, "verify_child",
                                               side_effect=verify):
                            with mock.patch.object(applied, "wait_restarted_promoted_core",
                                                   return_value=333) as waited:
                                with mock.patch.object(applied, "probe_isolated_routes") as probes:
                                    with mock.patch.object(applied, "probe_isolated_failure") as denial:
                                        result = applied.probe_supervised_crash_recovery(
                                            "/daemon.sock", 100, "/approved-core",
                                            5, 9, 222, 41001, node)
        self.assertEqual(result, 333)
        self.assertEqual(events, [
            ("verify", 222, 100, "/approved-core"),
            ("signal", 71, applied.signal.SIGKILL),
            ("verify", 333, 100, "/approved-core"),
        ])
        opened.assert_called_once_with(222)
        sent.assert_called_once_with(71, applied.signal.SIGKILL)
        closed.assert_called_once_with(71)
        waited.assert_called_once_with("/daemon.sock", 5, 9, 222)
        self.assertEqual(probes.call_args_list, [
            mock.call(41001, b"promoted-crash-recovered-", node),
            mock.call(41001, b"restored-after-crash-", node),
        ])
        denial.assert_called_once_with(41001, b"failed-after-crash-", node)

    def test_crash_injection_never_signals_unverified_process(self):
        for bad_pid, daemon_pid in ((0, 100), (1, 100), (100, 100),
                                    (-3, 100), (True, 100), (222, 1)):
            with self.subTest(pid=bad_pid, daemon=daemon_pid):
                with mock.patch.object(applied, "unix_json") as api:
                    with mock.patch.object(applied.os, "pidfd_open") as opened:
                        with self.assertRaises(RuntimeError):
                            applied.probe_supervised_crash_recovery(
                                "/sock", daemon_pid, "/approved-core",
                                5, 9, bad_pid, 41001, object())
                        api.assert_not_called()
                        opened.assert_not_called()

        valid = self.promoted_status(pid=222)
        drifted = self.promoted_status(pid=333)
        # Reject an already-replaced live PID *before* acquiring a pidfd.
        with mock.patch.object(applied, "unix_json", return_value=drifted):
            with mock.patch.object(applied.os, "pidfd_open") as opened:
                with mock.patch.object(applied.signal, "pidfd_send_signal") as sent:
                    with self.assertRaises(RuntimeError):
                        applied.probe_supervised_crash_recovery(
                            "/sock", 100, "/approved-core",
                            5, 9, 222, 41001, object())
                    opened.assert_not_called()
                    sent.assert_not_called()

        # An apparently valid pidfd must still be checked against a *fresh*
        # daemon snapshot; changed child identity refuses SIGKILL and closes fd.
        with mock.patch.object(applied, "unix_json", side_effect=[valid, drifted]):
            with mock.patch.object(applied.os, "pidfd_open", return_value=71):
                with mock.patch.object(applied.os, "close") as closed:
                    with mock.patch.object(applied, "verify_child") as verify:
                        with mock.patch.object(applied.signal,
                                               "pidfd_send_signal") as sent:
                            with self.assertRaises(RuntimeError):
                                applied.probe_supervised_crash_recovery(
                                    "/sock", 100, "/approved-core",
                                    5, 9, 222, 41001, object())
                            verify.assert_called_once_with(
                                222, 100, "/approved-core")
                            sent.assert_not_called()
                    closed.assert_called_once_with(71)

        with mock.patch.object(applied, "unix_json", return_value=valid):
            with mock.patch.object(applied.os, "pidfd_open", return_value=71):
                with mock.patch.object(applied.os, "close") as closed:
                    with mock.patch.object(applied, "verify_child",
                                           side_effect=RuntimeError("unowned Core")):
                        with mock.patch.object(applied.signal,
                                               "pidfd_send_signal") as sent:
                            with self.assertRaises(RuntimeError):
                                applied.probe_supervised_crash_recovery(
                                    "/sock", 100, "/approved-core",
                                    5, 9, 222, 41001, object())
                            sent.assert_not_called()
                    closed.assert_called_once_with(71)

        with mock.patch.object(applied, "unix_json", return_value=valid):
            with mock.patch.object(applied.os, "pidfd_open",
                                   side_effect=OSError("pidfd not permitted")):
                with mock.patch.object(applied.signal,
                                       "pidfd_send_signal") as sent:
                    with self.assertRaises(OSError):
                        applied.probe_supervised_crash_recovery(
                            "/sock", 100, "/approved-core",
                            5, 9, 222, 41001, object())
                    sent.assert_not_called()

    def test_short_lifecycle_daemon_fd_guard(self):
        with mock.patch.object(applied.os, "listdir",
                               return_value=["0", "1", "2", "3"]) as scanned:
            self.assertEqual(applied.daemon_fd_count(222), 4)
            scanned.assert_called_once_with("/proc/222/fd")
        for pid in (0, -2, 1, 2.0, True):
            with self.subTest(pid=pid):
                with self.assertRaises(RuntimeError):
                    applied.daemon_fd_count(pid)
        applied.assert_cycle_fd_budget(12, [13, 14, 13])
        for baseline, samples in (
            (0, [1, 2, 3]),
            (True, [1, 2, 3]),
            (12, [13, 14]),
            (12, [13, 14, 14.0]),
            (12, [13, 14, True]),
            (12, [13, 14, 40]),
            (12, [13, 13, 1024]),
            (12, [13, 14, -1]),
            (12, [10, 28, 15]),
        ):
            with self.subTest(baseline=baseline, samples=samples):
                with self.assertRaises(RuntimeError):
                    applied.assert_cycle_fd_budget(baseline, samples)

    def test_three_lifecycle_cycles_keep_same_promoted_generation(self):
        state = {"running": False, "next_pid": 400, "pid": 0}
        transitions = []
        class Node:
            pass
        node = Node()
        def status():
            result = self.promoted_status(pid=state["pid"])
            if not state["running"]:
                result.update({
                    "core_desired_state": "stopped",
                    "core_state": "stopped",
                    "core_pid": 0,
                })
            return result
        def command(argv, env, timeout=22):
            self.assertEqual(argv[:2], ["/app", "core"])
            self.assertEqual(env, {})
            if argv[2] == "start":
                self.assertFalse(state["running"])
                state["running"] = True
                state["next_pid"] += 1
                state["pid"] = state["next_pid"]
            elif argv[2] == "stop":
                self.assertTrue(state["running"])
                state["running"] = False
                state["pid"] = 0
            else:
                self.fail("unexpected CLI action")
            transitions.append(argv[2])
            return b""
        def wait(_app, _env, desired):
            self.assertEqual(desired, "running" if state["running"] else "stopped")
            return status()
        def unix(_sock, method, route, payload=None, expected=200, timeout=85):
            self.assertEqual((method, route), ("GET", "/v1/status"))
            return status()

        with mock.patch.object(applied, "unix_json", side_effect=unix):
            with mock.patch.object(applied.boot, "checked", side_effect=command):
                with mock.patch.object(applied, "wait_status", side_effect=wait):
                    with mock.patch.object(applied, "daemon_fd_count",
                                           side_effect=[12, 13, 14, 13]) as fds:
                        with mock.patch.object(applied, "verify_child") as child:
                            with mock.patch.object(applied, "probe_isolated_routes") as routes:
                                with mock.patch.object(applied, "probe_isolated_failure") as denial:
                                    with mock.patch.object(applied, "verify_stopped_ports") as closed:
                                        samples = applied.probe_bounded_lifecycle_cycles(
                                            "/app", {}, "/daemon.sock", 100,
                                            "/approved-core", 5, 9, 41001, node)
        self.assertEqual(samples, [13, 14, 13])
        self.assertEqual(transitions, ["start", "stop"] * 3)
        self.assertEqual(fds.call_count, 4)
        self.assertEqual(child.call_args_list, [
            mock.call(401, 100, "/approved-core"),
            mock.call(402, 100, "/approved-core"),
            mock.call(403, 100, "/approved-core"),
        ])
        self.assertEqual(routes.call_args_list, [
            mock.call(41001, b"lifecycle-0-", node),
            mock.call(41001, b"lifecycle-1-", node),
            mock.call(41001, b"lifecycle-restored-", node),
            mock.call(41001, b"lifecycle-2-", node),
        ])
        denial.assert_called_once_with(
            41001, b"lifecycle-refusal-", node)
        self.assertEqual(closed.call_count, 3)

    def test_short_lifecycle_rejects_implicit_running_initial_state(self):
        with mock.patch.object(applied, "unix_json",
                               return_value=self.promoted_status(pid=222)):
            with mock.patch.object(applied.boot, "checked") as command:
                with mock.patch.object(applied, "daemon_fd_count") as fds:
                    with self.assertRaises(RuntimeError):
                        applied.probe_bounded_lifecycle_cycles(
                            "/app", {}, "/daemon.sock", 100, "/approved-core",
                            5, 9, 41001, object())
                    command.assert_not_called()
                    fds.assert_not_called()

    def test_managed_proxy_port_and_payload_guards(self):
        for port in (0, 9999, 28080):
            with self.subTest(port=port):
                with self.assertRaises(RuntimeError):
                    applied.probe_port(port, 10000, b"x")
        with self.assertRaises(RuntimeError):
            applied.probe_port(2080, 10000, b"")

    def test_route_separation_requires_only_selected_to_dial_node(self):
        class Node:
            calls = 0
            failed = False

        def separated(port, echo_port, payload):
            self.assertEqual(echo_port, 40001)
            self.assertTrue(payload.endswith(str(port).encode()))
            if port == 2082:
                node.calls += 1

        node = Node()
        with mock.patch.object(applied, "probe_port", side_effect=separated):
            applied.probe_isolated_routes(40001, b"first-", node)
            applied.probe_isolated_routes(40001, b"restart-", node)
        self.assertEqual(node.calls, 2)

        def all_via_selected(port, echo_port, payload):
            node.calls += 1

        node = Node()
        with mock.patch.object(applied, "probe_port", side_effect=all_via_selected):
            with self.assertRaises(RuntimeError):
                applied.probe_isolated_routes(40001, b"bad-", node)

        node = Node()
        with mock.patch.object(applied, "probe_port", return_value=None):
            with self.assertRaises(RuntimeError):
                applied.probe_isolated_routes(40001, b"bypass-", node)

        def failed_node(port, echo_port, payload):
            if port == 2082:
                node.calls += 1
                node.failed = True

        node = Node()
        with mock.patch.object(applied, "probe_port", side_effect=failed_node):
            with self.assertRaises(RuntimeError):
                applied.probe_isolated_routes(40001, b"fail-", node)

    def test_fail_closed_selected_reply_is_not_a_success_or_timeout(self):
        class FakeConn:
            def __init__(self, response):
                self.parts = [b"\x05\x00", response]
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                pass
            def settimeout(self, _seconds):
                pass
            def sendall(self, _data):
                pass
            def recv(self, _size):
                return self.parts.pop(0) if self.parts else b""

        for response in (b"", b"\x05\x05", b"\x05\x01"):
            with self.subTest(allowed_failure=response):
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=FakeConn(response)):
                    applied.probe_selected_refusal(41001)
        for response in (b"\x05\x00", b"\x04\x01", b"\x05"):
            with self.subTest(forbidden_reply=response):
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=FakeConn(response)):
                    with self.assertRaises(RuntimeError):
                        applied.probe_selected_refusal(41001)
        for port in (-1, 0, 65536, True):
            with self.subTest(invalid_port=port):
                with self.assertRaises(RuntimeError):
                    applied.probe_selected_refusal(port)

    def test_selected_failure_isolates_other_ports_and_recovers(self):
        class Node:
            calls = 0
            rejections = 0
            reject_connections = False
            failed = False
        node = Node()

        def local_route(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            self.assertTrue(payload.endswith(str(port).encode()))
            if port == 2082:
                self.assertFalse(node.reject_connections)
                node.calls += 1

        def rejected(echo_port):
            self.assertEqual(echo_port, 41001)
            self.assertTrue(node.reject_connections)
            node.rejections += 1

        with mock.patch.object(applied, "probe_port", side_effect=local_route):
            with mock.patch.object(applied, "probe_selected_refusal",
                                   side_effect=rejected):
                applied.probe_isolated_routes(41001, b"before-", node)
                applied.probe_isolated_failure(41001, b"failed-", node)
                self.assertFalse(node.reject_connections)
                applied.probe_isolated_routes(41001, b"restored-", node)
        self.assertEqual((node.calls, node.rejections), (2, 1))
        self.assertFalse(node.failed)

        node = Node()
        def wrong_direct(port, _echo_port, _payload):
            if port == 2080:
                node.calls += 1
        with mock.patch.object(applied, "probe_port", side_effect=wrong_direct):
            with self.assertRaises(RuntimeError):
                applied.probe_isolated_failure(41001, b"bad-", node)
        self.assertFalse(node.reject_connections)

        node = Node()
        with mock.patch.object(applied, "probe_port", return_value=None):
            with mock.patch.object(applied, "probe_selected_refusal",
                                   return_value=None):
                with self.assertRaises(RuntimeError):
                    applied.probe_isolated_failure(41001, b"bypass-", node)
        self.assertFalse(node.reject_connections)

        node = Node()
        def node_broken(_echo_port):
            node.rejections += 1
            node.failed = True
        with mock.patch.object(applied, "probe_port", return_value=None):
            with mock.patch.object(applied, "probe_selected_refusal",
                                   side_effect=node_broken):
                with self.assertRaises(RuntimeError):
                    applied.probe_isolated_failure(41001, b"fault-", node)
        self.assertFalse(node.reject_connections)

    def test_synthetic_socks_node_refusal_never_forwards_to_echo(self):
        with applied.LocalSocksServer(("127.0.0.1", 0), applied.LocalSocksNode) as srv:
            srv.echo_port = 41001
            srv.reject_connections = True
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                with mock.patch.object(applied.socket, "create_connection",
                                       side_effect=AssertionError("unapproved TCP dial")):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)
                        sock.connect(srv.server_address)
                        sock.sendall(b"\x05\x01\x00")
                        self.assertEqual(applied.exact_read(sock, 2), b"\x05\x00")
                        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                                     struct.pack("!H", 41001))
                        self.assertEqual(applied.exact_read(sock, 10),
                                         b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00")
                self.assertEqual(srv.rejections, 1)
                self.assertEqual(srv.calls, 0)
                self.assertFalse(srv.failed)
            finally:
                srv.shutdown()
                thread.join(timeout=3)

    def test_node_rejects_nonlocal_connect_without_outbound_dial(self):
        with applied.LocalSocksServer(("127.0.0.1", 0), applied.LocalSocksNode) as srv:
            srv.echo_port = 40892
            srv.calls = 0
            srv.failed = False
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                with mock.patch.object(applied.socket, "create_connection",
                                       side_effect=AssertionError("external dial")):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)
                        sock.connect(srv.server_address)
                        sock.sendall(b"\x05\x01\x00")
                        self.assertEqual(applied.exact_read(sock, 2), b"\x05\x00")
                        sock.sendall(b"\x05\x01\x00\x01\x08\x08\x08\x08" +
                                     struct.pack("!H", 53))
                # Threaded request handler rejects before creating any outgoing socket.
                for _ in range(50):
                    if srv.failed:
                        break
                    threading.Event().wait(0.02)
                self.assertTrue(srv.failed)
                self.assertEqual(srv.calls, 0)
            finally:
                srv.shutdown()
                thread.join(timeout=3)

    def test_unix_http_api_is_strictly_local_and_bounded(self):
        with self.assertRaises(RuntimeError):
            applied.unix_json("/fake/sock", "POST",
                              "/v1/anything-else", {"x": 1})
        with self.assertRaises(RuntimeError):
            applied.unix_json("/fake/sock", "POST",
                              "/v1/declaration", {"oversized": "x" * 8192})

    def test_unix_client_is_closed_on_success_and_error(self):
        class DummyResponse:
            status = 200
            def read(self, _limit):
                return b'{"api_version":"v1"}'

        clients = []
        class DummyClient:
            def __init__(self, path, timeout):
                self.path = path
                self.timeout = timeout
                self.closed = False
                clients.append(self)
            def request(self, method, route, body=None, headers=None):
                self.method = method
                self.route = route
            def getresponse(self):
                return DummyResponse()
            def close(self):
                self.closed = True

        with mock.patch.object(applied, "UnixHTTP", DummyClient):
            doc = applied.unix_json("/test.sock", "GET", "/v1/status")
            self.assertEqual(doc["api_version"], "v1")
            self.assertTrue(clients[-1].closed)
            with self.assertRaises(RuntimeError):
                applied.unix_json("/test.sock", "GET", "/v1/status",
                                  expected=201)
            self.assertTrue(clients[-1].closed)

    def test_workflow_requires_four_separate_native_network_none_probes(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/core-provenance.yml").read_text()
        self.assertEqual(workflow.count("docker run --rm --pull never"), 4)
        self.assertEqual(workflow.count("--network none --cap-drop ALL"), 4)
        self.assertEqual(workflow.count("--user 10001:10001 --read-only"), 4)
        self.assertIn("t24_airgap_managed_applied.py", workflow)
        self.assertIn("--core-sha256 \"$expected_core_sha\"", workflow)
        self.assertIn("docker.io/library/python@sha256:", workflow)


if __name__ == "__main__":
    unittest.main()
