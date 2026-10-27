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
    @staticmethod
    def synthetic_http_origin():
        class Origin:
            server_address = ("127.0.0.1", 41002)

            def __init__(self):
                self.receipts = []
                self.counter_lock = threading.Lock()
        return Origin()

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


    def test_held_crash_closes_three_tunnels_and_reuses_one_verified_kill(self):
        class Node:
            calls = 5
            rejections = 3
            failed = False
            reject_connections = False

        class Held:
            def __init__(self):
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True

        node = Node()
        opened = []
        opened_http = []
        def open_tunnel(port, target, payload):
            self.assertEqual(target, 41001)
            self.assertEqual(payload, b"held-crash-" + str(port).encode())
            held = Held()
            opened.append(held)
            if port == 2082:
                node.calls += 1
            return held
        def open_http(port, target, payload):
            self.assertEqual(target, 41001)
            self.assertEqual(payload,
                             b"held-http-crash-" + str(port).encode())
            held = Held()
            opened_http.append(held)
            if port == 2082:
                node.calls += 1
            return held
        def crash(*args):
            self.assertEqual(args, (
                "/daemon.sock", 100, "/approved-core", 5, 9, 222, 41001, node))
            node.calls += 2  # Existing recovery probes two new Selected relays.
            node.rejections += 1
            return 333

        with mock.patch.object(applied, "unix_json",
                               return_value=self.promoted_status(pid=222)) as api:
            with mock.patch.object(applied, "open_held_socks_echo",
                                   side_effect=open_tunnel) as opened_call:
                with mock.patch.object(applied, "open_held_http_echo",
                                       side_effect=open_http) as opened_http_call:
                    with mock.patch.object(applied, "probe_supervised_crash_recovery",
                                           side_effect=crash) as kill:
                        with mock.patch.object(applied, "assert_held_session_closed") as eof:
                            with mock.patch.object(applied, "assert_held_http_closed") as http_eof:
                                stages = []
                                result = applied.probe_held_crash_recovery(
                                    "/daemon.sock", 100, "/approved-core",
                                    5, 9, 222, 41001, node,
                                    stage_hook=stages.append)
        self.assertEqual(stages, [
            "crash-held-preflight", "crash-held-open-2080",
            "crash-held-open-2081", "crash-held-open-2082",
            "crash-held-http-open-2080", "crash-held-http-open-2081",
            "crash-held-http-open-2082",
            "crash-held-pid-check", "crash-held-supervised-recovery",
            "crash-held-sockets-closed", "crash-held-http-sockets-closed",
            "crash-held-node-audit",
        ])
        self.assertEqual(result, 333)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(opened_call.call_count, 3)
        self.assertEqual(opened_http_call.call_count, 3)
        kill.assert_called_once()
        self.assertEqual(eof.call_args_list,
                         [mock.call(conn) for conn in opened])
        self.assertEqual(http_eof.call_args_list,
                         [mock.call(conn) for conn in opened_http])
        self.assertTrue(all(conn.closed for conn in opened + opened_http))
        self.assertEqual((node.calls, node.rejections), (9, 4))

    def test_invalid_crash_diagnostic_hook_never_contacts_core(self):
        with mock.patch.object(applied, "unix_json") as api:
            with mock.patch.object(applied, "open_held_socks_echo") as dial:
                with mock.patch.object(applied, "probe_supervised_crash_recovery") as kill:
                    with self.assertRaises(RuntimeError):
                        applied.probe_held_crash_recovery(
                            "/daemon.sock", 100, "/approved-core",
                            5, 9, 222, 41001, object(), stage_hook="unsafe")
                    api.assert_not_called()
                    dial.assert_not_called()
                    kill.assert_not_called()

    def test_held_crash_fails_closed_before_signal_on_drift_or_bypass(self):
        class Node:
            calls = 5
            rejections = 3
            failed = False
            reject_connections = False

        class Held:
            def __init__(self):
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True

        args = ("/daemon.sock", 100, "/approved-core", 5, 9,
                222, 41001)
        good = self.promoted_status(pid=222)
        drift = dict(good, core_pid=444)
        with mock.patch.object(applied, "unix_json", return_value=drift):
            with mock.patch.object(applied, "open_held_socks_echo") as dial:
                with mock.patch.object(applied, "probe_supervised_crash_recovery") as kill:
                    with self.assertRaises(RuntimeError):
                        applied.probe_held_crash_recovery(*args, Node())
                    dial.assert_not_called()
                    kill.assert_not_called()
        for attr in ("failed", "reject_connections"):
            node = Node()
            setattr(node, attr, True)
            with mock.patch.object(applied, "unix_json") as api:
                with mock.patch.object(applied, "open_held_socks_echo") as dial:
                    with self.assertRaises(RuntimeError):
                        applied.probe_held_crash_recovery(*args, node)
                    api.assert_not_called()
                    dial.assert_not_called()

        for defect in ("pid-drift", "Rule-crosses-Selected",
                       "HTTP-Rule-crosses-Selected", "HTTP-open-fails",
                       "crash-error", "old-tunnel-still-live",
                       "old-HTTP-tunnel-still-live"):
            with self.subTest(defect=defect):
                node = Node()
                opened = []
                def connect(port, _echo, _payload):
                    held = Held()
                    opened.append(held)
                    if port == 2082 or (defect == "Rule-crosses-Selected" and
                                        port == 2080):
                        node.calls += 1
                    return held
                def http_connect(port, _echo, _payload):
                    if defect == "HTTP-open-fails" and port == 2081:
                        raise RuntimeError("injected HTTP tunnel open failure")
                    held = Held()
                    opened.append(held)
                    if (port == 2082 or
                            (defect == "HTTP-Rule-crosses-Selected"
                             and port == 2080)):
                        node.calls += 1
                    return held
                def crashed(*_args):
                    node.calls += 2
                    node.rejections += 1
                    if defect == "crash-error":
                        raise RuntimeError("injected Core restart failure")
                    return 333
                statuses = ([good, drift] if defect == "pid-drift"
                            else [good, good])
                with mock.patch.object(applied, "unix_json",
                                       side_effect=statuses):
                    with mock.patch.object(applied, "open_held_socks_echo",
                                           side_effect=connect):
                        with mock.patch.object(applied, "open_held_http_echo",
                                               side_effect=http_connect):
                            with mock.patch.object(
                                    applied, "probe_supervised_crash_recovery",
                                    side_effect=crashed) as kill:
                                with mock.patch.object(
                                        applied, "assert_held_session_closed",
                                        side_effect=(RuntimeError("old socket alive")
                                                     if defect == "old-tunnel-still-live"
                                                     else None)):
                                    with mock.patch.object(
                                            applied, "assert_held_http_closed",
                                            side_effect=(RuntimeError("old HTTP tunnel alive")
                                                         if defect == "old-HTTP-tunnel-still-live"
                                                         else None)):
                                        with self.assertRaises(RuntimeError):
                                            applied.probe_held_crash_recovery(
                                                *args, node)
                                if defect in ("pid-drift", "Rule-crosses-Selected",
                                              "HTTP-Rule-crosses-Selected",
                                              "HTTP-open-fails"):
                                    kill.assert_not_called()
                                else:
                                    kill.assert_called_once()
                self.assertTrue(all(conn.closed for conn in opened))


    def test_post_crash_selected_route_ledger_includes_held_http_and_fails_closed(self):
        class Node:
            def __init__(self):
                self.calls = 13
                self.rejections = 5
                self.reject_connections = False
                self.failed = False

        applied.assert_post_crash_selected_accounting(Node())
        for defect in ("missing-http-hop", "extra-hop", "missing-refusal",
                       "rejecting", "failed", "invalid-counter"):
            with self.subTest(defect=defect):
                node = Node()
                if defect == "missing-http-hop":
                    node.calls = 12  # Old SOCKS-only ledger, now invalid.
                elif defect == "extra-hop":
                    node.calls = 14
                elif defect == "missing-refusal":
                    node.rejections = 4
                elif defect == "rejecting":
                    node.reject_connections = True
                elif defect == "failed":
                    node.failed = True
                elif defect == "invalid-counter":
                    node.calls = True
                with self.assertRaises(RuntimeError) as ctx:
                    applied.assert_post_crash_selected_accounting(node)
                self.assertEqual(
                    applied.safe_airgap_failure_code(ctx.exception),
                    "crash-post-stop-selected-accounting")
        self.assertEqual(
            applied.safe_airgap_failure_code(
                RuntimeError("crash secret path token 123")),
            "unclassified")

    def test_held_http_crash_error_code_remains_fixed_and_redacted(self):
        self.assertEqual(
            applied.safe_airgap_failure_code(RuntimeError(
                "held HTTP crash tunnel crossed or skipped Selected")),
            "crash-held-http-route-bypass")
        self.assertEqual(
            applied.safe_airgap_failure_code(RuntimeError(
                "stopped Core forwarded data on held HTTP CONNECT tunnel")),
            "held-http-still-forwarding")
        self.assertEqual(
            applied.safe_airgap_failure_code(RuntimeError(
                "local private tunnel path HTTP auth=not-for-logs")),
            "unclassified")

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
        def stop_held(app, env, sock, echo_port, target,
                      old_generation, promoted_generation, expected_pid):
            self.assertEqual(
                (app, env, sock, echo_port, target,
                 old_generation, promoted_generation, expected_pid),
                ("/app", {}, "/daemon.sock", 41001, node, 5, 9, 403))
            command([app, "core", "stop"], env, timeout=20)
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
                                        with mock.patch.object(
                                            applied, "probe_bounded_parallel_routes",
                                            return_value=12) as parallel:
                                            with mock.patch.object(
                                                applied, "probe_parallel_selected_denials",
                                                return_value=12) as denied_parallel:
                                                with mock.patch.object(
                                                    applied, "stop_core_with_held_tunnels",
                                                    side_effect=stop_held) as held:
                                                    stages = []
                                                    samples = applied.probe_bounded_lifecycle_cycles(
                                                        "/app", {}, "/daemon.sock", 100,
                                                        "/approved-core", 5, 9, 41001, node,
                                                        stage_hook=stages.append)
        self.assertEqual(stages, [
            "held-lifecycle-preflight",
            "held-lifecycle-cycle-0-start",
            "held-lifecycle-cycle-0-routes",
            "held-lifecycle-cycle-0-stop",
            "held-lifecycle-cycle-0-stopped-audit",
            "held-lifecycle-cycle-1-start",
            "held-lifecycle-cycle-1-routes",
            "held-lifecycle-cycle-1-selected-refusal",
            "held-lifecycle-cycle-1-stop",
            "held-lifecycle-cycle-1-stopped-audit",
            "held-lifecycle-cycle-2-start",
            "held-lifecycle-cycle-2-routes",
            "held-lifecycle-cycle-2-parallel",
            "held-lifecycle-cycle-2-stop",
            "held-lifecycle-cycle-2-stopped-audit",
            "held-lifecycle-fd-budget",
        ])
        held.assert_called_once_with(
            "/app", {}, "/daemon.sock", 41001, node, 5, 9, 403)
        self.assertEqual(parallel.call_args_list, [
            mock.call(41001, node), mock.call(41001, node),
        ])
        denied_parallel.assert_called_once_with(41001, node)
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


    def test_native_failure_codes_are_strict_allow_list_without_secrets(self):
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("Daemon FD count drifted during short lifecycle smoke")),
            "daemon-fd-drift")
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("managed Core ports stayed open after stop")),
            "proxy-listener-open")
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("stopped Core still relayed data on a held SOCKS5 connection")),
            "held-stream-not-closed")
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("held crash tunnel crossed Selected or skipped its node")),
            "crash-held-route-bypass")
        for unsafe in (
            RuntimeError("token=secret-danger HTTP://upstream/private"),
            RuntimeError("held-session secret \n malicious-looking-label"),
            ValueError("managed Core ports stayed open after stop"),
            OSError("Daemon FD count drifted during short lifecycle smoke"),
            RuntimeError(""),
        ):
            with self.subTest(exception=type(unsafe).__name__):
                self.assertEqual(
                    applied.safe_airgap_failure_code(unsafe), "unclassified")
        self.assertTrue(all(
            isinstance(code, str) and code.isascii() and
            code.replace("-", "").islower()
            for code in applied.AIRGAP_FAILURE_CODES.values()))


    def test_run_daemon_waits_for_stable_stopped_status_not_just_configured(self):
        stable = {
            "api_version": "v1", "core_configured": True,
            "core_desired_state": "stopped", "core_state": "stopped",
            "core_pid": 0, "recovery_required": False,
            "core_circuit_open": False, "active_operation": "",
        }
        transient = [
            dict(stable, core_state="starting"),
            dict(stable, core_pid=31337),
            dict(stable, recovery_required=True),
            dict(stable, active_operation="declaration-apply"),
            stable,
        ]
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            env = {"XDG_RUNTIME_DIR": dirname}
            proc = mock.Mock(pid=100)
            proc.poll.return_value = None
            proc.wait.return_value = 0
            seen = []
            def work(process, sock, initial):
                self.assertIs(process, proc)
                self.assertEqual(sock, root / "karing-tui-v2" / "daemon.sock")
                seen.append(initial)
                return "ready"
            with mock.patch.object(applied.subprocess, "Popen",
                                   return_value=proc) as popen:
                with mock.patch.object(applied.boot, "checked",
                                       side_effect=[json.dumps(s) for s in transient]) as cli:
                    with mock.patch.object(applied.time, "sleep") as sleep:
                        self.assertEqual(applied.run_daemon(
                            "/app", "/core", root, env, work), "ready")
            self.assertEqual(seen, [stable])
            self.assertEqual(cli.call_count, 5)
            self.assertEqual(sleep.call_count, 4)
            self.assertEqual(popen.call_count, 1)
            proc.send_signal.assert_called_once_with(applied.signal.SIGTERM)
            proc.wait.assert_called_once_with(timeout=15)

    def test_run_daemon_never_accepts_implicit_running_core(self):
        bad = {
            "api_version": "v1", "core_configured": True,
            "core_desired_state": "running", "core_state": "running",
            "core_pid": 31337, "recovery_required": False,
            "core_circuit_open": False, "active_operation": "",
        }
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            env = {"XDG_RUNTIME_DIR": dirname}
            proc = mock.Mock(pid=100)
            proc.poll.return_value = None
            proc.wait.return_value = 0
            with mock.patch.object(applied.subprocess, "Popen", return_value=proc):
                with mock.patch.object(applied.boot, "checked",
                                       return_value=json.dumps(bad)) as cli:
                    with mock.patch.object(applied.time, "sleep") as sleep:
                        with self.assertRaises(RuntimeError):
                            applied.run_daemon(
                                "/app", "/core", root, env,
                                lambda *_args: self.fail("unexpected callback"))
            cli.assert_called_once()
            sleep.assert_not_called()
            proc.send_signal.assert_called_once_with(applied.signal.SIGTERM)
            self.assertEqual(applied.safe_airgap_failure_code(
                RuntimeError("managed Daemon reopened Core without stopped intent")),
                "daemon-implicit-core-start")

    def test_short_lifecycle_rejects_invalid_diagnostic_hook_without_start(self):
        with mock.patch.object(applied, "unix_json") as api:
            with mock.patch.object(applied.boot, "checked") as cli:
                with self.assertRaises(RuntimeError):
                    applied.probe_bounded_lifecycle_cycles(
                        "/app", {}, "/daemon.sock", 100, "/approved-core",
                        5, 9, 41001, object(), stage_hook="unsafe")
                api.assert_not_called()
                cli.assert_not_called()

    def test_six_parallel_workers_prove_selected_only_and_distinct_echoes(self):
        class Node:
            def __init__(self):
                self.calls = 5
                self.rejections = 2
                self.failed = False
                self.reject_connections = False
                self.parallel_payloads = []

        node = Node()
        received = []
        lock = threading.Lock()

        def fake_probe(port, target, payload):
            self.assertEqual(target, 41001)
            self.assertIn(port, applied.MANAGED_PORTS)
            self.assertTrue(payload.startswith(b"parallel-"))
            self.assertTrue(payload.endswith(str(port).encode()))
            with lock:
                received.append((port, payload))
                if port == 2082:
                    node.calls += 1
                    node.parallel_payloads.append(payload)

        with mock.patch.object(applied, "probe_port", side_effect=fake_probe) as probe:
            self.assertEqual(applied.probe_bounded_parallel_routes(41001, node), 12)
        self.assertEqual(probe.call_count, 12)
        self.assertEqual(len({payload for _, payload in received}), 12)
        self.assertEqual([sum(port == x for port, _ in received)
                          for x in applied.MANAGED_PORTS], [4, 4, 4])
        self.assertEqual((node.calls, node.rejections), (9, 2))
        self.assertFalse(node.failed)

    def test_parallel_audit_tag_is_fixed_and_rejects_invalid_identity(self):
        payloads = [
            applied.parallel_probe_payload(i, iteration, applied.MANAGED_PORTS[i % 3])
            for i in range(6) for iteration in (0, 1)
        ]
        self.assertEqual(len(set(payloads)), 12)
        self.assertTrue(all(len(payload) == 32 for payload in payloads))
        for invalid in ((-1, 0, 2082), (6, 1, 2082), (True, 0, 2082),
                        (1, -1, 2082), (1, True, 2082),
                        (1, 0, 2082.0), (1, 0, 2089)):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RuntimeError):
                    applied.parallel_probe_payload(*invalid)

    def test_parallel_probe_refuses_misroutes_failures_and_invalid_inputs(self):
        class Node:
            def __init__(self):
                self.calls = 5
                self.rejections = 2
                self.failed = False
                self.reject_connections = False
                self.parallel_payloads = []

        for bad_port in (0, -1, 65536, True, 3.5):
            with self.subTest(bad_port=bad_port):
                with mock.patch.object(applied, "probe_port") as probe:
                    with self.assertRaises(RuntimeError):
                        applied.probe_bounded_parallel_routes(bad_port, Node())
                    probe.assert_not_called()

        for defect in ("selected-bypass", "Rule-crossed", "compensating-cross",
                       "upstream-refused", "upstream-failed", "worker-error"):
            with self.subTest(defect=defect):
                node = Node()
                lock = threading.Lock()

                def corrupt(port, _target, payload):
                    with lock:
                        if defect == "worker-error" and port == 2081:
                            raise RuntimeError("local proxy refused TCP")
                        skip_selected = (defect == "compensating-cross" and
                                         payload == applied.parallel_probe_payload(
                                             5, 1, 2082))
                        if port == 2082 and defect != "selected-bypass" and not skip_selected:
                            node.calls += 1
                            node.parallel_payloads.append(payload)
                        if port == 2080 and defect == "Rule-crossed":
                            node.calls += 1
                            node.parallel_payloads.append(payload)
                        if (defect == "compensating-cross" and
                                payload == applied.parallel_probe_payload(0, 0, 2080)):
                            node.calls += 1
                            node.parallel_payloads.append(payload)
                        if port == 2082 and defect == "upstream-refused":
                            node.rejections += 1
                        if port == 2082 and defect == "upstream-failed":
                            node.failed = True

                with mock.patch.object(applied, "probe_port", side_effect=corrupt):
                    with self.assertRaises(RuntimeError):
                        applied.probe_bounded_parallel_routes(41001, node)

        for invalid_field, value in (
            ("calls", -1), ("calls", True), ("rejections", -1),
            ("rejections", None), ("parallel_payloads", None),
            ("failed", True), ("reject_connections", True),
        ):
            with self.subTest(invalid_field=invalid_field):
                node = Node()
                setattr(node, invalid_field, value)
                with mock.patch.object(applied, "probe_port") as probe:
                    with self.assertRaises(RuntimeError):
                        applied.probe_bounded_parallel_routes(41001, node)
                    probe.assert_not_called()

    def test_parallel_selected_denials_isolate_other_inbounds_then_reset(self):
        class Node:
            def __init__(self):
                self.calls = 8
                self.rejections = 3
                self.parallel_payloads = [b"prior"]
                self.failed = False
                self.reject_connections = False

        node = Node()
        lock = threading.Lock()
        routed = []
        rejected_ports = []

        def healthy(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            self.assertIn(port, (2080, 2081))
            self.assertTrue(payload.startswith(b"parallel-denied-"))
            self.assertTrue(payload.endswith(str(port).encode()))
            self.assertTrue(node.reject_connections)
            with lock:
                routed.append((port, payload))

        def refused(echo_port):
            self.assertEqual(echo_port, 41001)
            self.assertTrue(node.reject_connections)
            with lock:
                node.rejections += 1
                rejected_ports.append(echo_port)

        with mock.patch.object(applied, "probe_port", side_effect=healthy) as probes:
            with mock.patch.object(applied, "probe_selected_refusal",
                                   side_effect=refused) as denied:
                self.assertEqual(applied.probe_parallel_selected_denials(
                    41001, node), 12)
        self.assertEqual(probes.call_count, 8)
        self.assertEqual(denied.call_count, 4)
        self.assertEqual([sum(p == port for p, _ in routed)
                          for port in (2080, 2081)], [4, 4])
        self.assertEqual(len({payload for _, payload in routed}), 8)
        self.assertEqual(rejected_ports, [41001] * 4)
        self.assertEqual((node.calls, node.rejections), (8, 7))
        self.assertEqual(node.parallel_payloads, [b"prior"])
        self.assertFalse(node.reject_connections)

    def test_parallel_refusal_rejects_bypass_cross_routes_and_bad_upstream(self):
        class Node:
            def __init__(self):
                self.calls = 8
                self.rejections = 3
                self.parallel_payloads = [b"prior"]
                self.failed = False
                self.reject_connections = False

        for bad_port in (0, -1, True, 65536, 40000.0):
            with self.subTest(port=bad_port):
                node = Node()
                with mock.patch.object(applied, "probe_port") as probe:
                    with mock.patch.object(applied, "probe_selected_refusal") as refusal:
                        with self.assertRaises(RuntimeError):
                            applied.probe_parallel_selected_denials(bad_port, node)
                    probe.assert_not_called()
                    refusal.assert_not_called()
                self.assertFalse(node.reject_connections)

        for name in ("selected-bypass", "rule-crossed", "denial-storm",
                     "synthetic-node-failed", "healthy-inbound-failed",
                     "reported-success"):
            with self.subTest(name=name):
                node = Node()
                lock = threading.Lock()
                def healthy(port, _echo_port, _payload):
                    if name == "healthy-inbound-failed" and port == 2080:
                        raise RuntimeError("direct socket failed")
                    with lock:
                        if name == "rule-crossed" and port == 2080:
                            node.calls += 1
                def refusal(_echo_port):
                    if name == "reported-success":
                        raise RuntimeError("Selected returned SOCKS success")
                    with lock:
                        if name != "selected-bypass":
                            node.rejections += 5 if name == "denial-storm" else 1
                        if name == "synthetic-node-failed":
                            node.failed = True
                with mock.patch.object(applied, "probe_port", side_effect=healthy):
                    with mock.patch.object(applied, "probe_selected_refusal",
                                           side_effect=refusal):
                        with self.assertRaises(RuntimeError):
                            applied.probe_parallel_selected_denials(41001, node)
                self.assertFalse(node.reject_connections)

        for attr, value in (
            ("calls", True), ("calls", -1), ("rejections", None),
            ("rejections", -1), ("parallel_payloads", None),
            ("failed", True), ("reject_connections", True),
        ):
            with self.subTest(attribute=attr):
                node = Node()
                setattr(node, attr, value)
                with mock.patch.object(applied, "probe_port") as probe:
                    with self.assertRaises(RuntimeError):
                        applied.probe_parallel_selected_denials(41001, node)
                    probe.assert_not_called()

    def test_open_held_socks_echo_retains_live_connection_and_closes_on_error(self):
        class Conn:
            def __init__(self):
                self.closed = False
                self.writes = []
                self.timeout = None
            def settimeout(self, value):
                self.timeout = value
            def sendall(self, payload):
                self.writes.append(payload)
            def close(self):
                self.closed = True

        payload = b"held-stop-2082"
        for port in applied.MANAGED_PORTS:
            with self.subTest(port=port):
                conn = Conn()
                replies = [b"\x05\x00", b"\x05\x00\x00\x01",
                           b"\x7f\x00\x00\x01", b"\x00\x00",
                           loopback.REPLY_PREFIX + payload]
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as opened:
                    with mock.patch.object(applied, "exact_read",
                                           side_effect=replies):
                        self.assertIs(
                            applied.open_held_socks_echo(port, 41001, payload), conn)
                opened.assert_called_once_with(("127.0.0.1", port), timeout=4)
                self.assertFalse(conn.closed)
                self.assertEqual(conn.timeout, 4)
                self.assertEqual(conn.writes[0], b"\x05\x01\x00")
                self.assertEqual(conn.writes[-1], payload)
                conn.close()
                self.assertTrue(conn.closed)

        for replies in (
            [b"\x05\x02"],
            [b"\x05\x00", b"\x05\x05\x00\x01"],
            [b"\x05\x00", b"\x05\x00\x00\x09"],
            [b"\x05\x00", b"\x05\x00\x00\x01",
             b"\x7f\x00\x00\x01", b"\x00\x00", b"wrong"],
        ):
            conn = Conn()
            with mock.patch.object(applied.socket, "create_connection",
                                   return_value=conn):
                with mock.patch.object(applied, "exact_read",
                                       side_effect=replies):
                    with self.assertRaises(RuntimeError):
                        applied.open_held_socks_echo(2082, 41001, payload)
            self.assertTrue(conn.closed)

        for port, target, message in ((2089, 41001, payload),
                                       (True, 41001, payload),
                                       (2082, 0, payload),
                                       (2082, 65536, payload),
                                       (2082, True, payload),
                                       (2082, 41001, b""),
                                       (2082, 41001, "not-bytes")):
            with self.subTest(port=port, target=target, message=message):
                with mock.patch.object(applied.socket, "create_connection") as opened:
                    with self.assertRaises(RuntimeError):
                        applied.open_held_socks_echo(port, target, message)
                    opened.assert_not_called()

    def test_held_session_must_close_after_explicit_stop(self):
        for received in (b"", ConnectionResetError("reset"),
                         ConnectionAbortedError("aborted")):
            with self.subTest(received=str(received)):
                conn = mock.Mock()
                conn.recv.side_effect = (received if isinstance(received, Exception)
                                         else None)
                if isinstance(received, bytes):
                    conn.recv.return_value = received
                applied.assert_held_session_closed(conn)
                conn.settimeout.assert_called_once_with(3)
                conn.recv.assert_called_once_with(1)

        for received in (b"still forwarding", socket.timeout("old socket open")):
            with self.subTest(received=str(received)):
                conn = mock.Mock()
                if isinstance(received, bytes):
                    conn.recv.return_value = received
                else:
                    conn.recv.side_effect = received
                with self.assertRaises((RuntimeError, socket.timeout)):
                    applied.assert_held_session_closed(conn)

    def test_held_stop_closes_three_sessions_and_refuses_wrong_routes(self):
        class Node:
            def __init__(self):
                self.calls = 9
                self.failed = False
                self.reject_connections = False

        class Held:
            def __init__(self):
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True

        node = Node()
        opened = []
        def connect(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            self.assertEqual(payload, b"held-stop-" + str(port).encode())
            c = Held()
            opened.append(c)
            if port == 2082:
                node.calls += 1
            return c
        stopped = self.status("stopped", False)
        running = self.promoted_status(pid=222)
        with (mock.patch.object(applied, "unix_json", return_value=running),
              mock.patch.object(applied, "open_held_socks_echo",
                                side_effect=connect) as dial):
            with mock.patch.object(applied.boot, "checked") as cli:
                with mock.patch.object(applied, "wait_status",
                                       return_value=stopped) as status:
                    with mock.patch.object(applied, "assert_held_session_closed") as eof:
                        self.assertIs(applied.stop_core_with_held_tunnels(
                            "/app", {}, "/daemon.sock", 41001, node,
                            5, 9, 222), stopped)
        self.assertEqual(dial.call_count, 3)
        cli.assert_called_once_with(["/app", "core", "stop"], {}, timeout=20)
        status.assert_called_once_with("/app", {}, "stopped")
        self.assertEqual(eof.call_args_list,
                         [mock.call(c) for c in opened])
        self.assertTrue(all(c.closed for c in opened))
        self.assertEqual(node.calls, 10)

        for defect in ("Rule-selected-cross", "Selected-bypass", "old-connection-open"):
            with self.subTest(defect=defect):
                node = Node()
                opened = []
                def bad_connect(port, _echo_port, _payload):
                    c = Held()
                    opened.append(c)
                    if port == 2080 and defect == "Rule-selected-cross":
                        node.calls += 1
                    if port == 2082 and defect != "Selected-bypass":
                        node.calls += 1
                    return c
                with (mock.patch.object(applied, "unix_json", return_value=running),
                      mock.patch.object(applied, "open_held_socks_echo",
                                        side_effect=bad_connect)):
                    with mock.patch.object(applied.boot, "checked") as cli:
                        with mock.patch.object(applied, "wait_status",
                                               return_value=stopped):
                            with mock.patch.object(
                                applied, "assert_held_session_closed",
                                side_effect=(RuntimeError("old TCP still live")
                                             if defect == "old-connection-open"
                                             else None)):
                                with self.assertRaises(RuntimeError):
                                    applied.stop_core_with_held_tunnels(
                                        "/app", {}, "/daemon.sock", 41001, node,
                                        5, 9, 222)
                        if defect == "old-connection-open":
                            cli.assert_called_once()
                        else:
                            cli.assert_not_called()
                self.assertTrue(all(c.closed for c in opened))

        # A stopped, replaced, or unapproved Core must never be signaled
        # via the held-session stop test, even if its TCP port still accepts.
        for bad_status in (
            dict(running, core_pid=333),
            dict(running, config_revision=1),
            dict(running, last_known_good_generation_id=5),
            dict(running, recovery_required=True),
        ):
            node = Node()
            with mock.patch.object(applied, "unix_json",
                                   return_value=bad_status):
                with mock.patch.object(applied, "open_held_socks_echo") as opened:
                    with mock.patch.object(applied.boot, "checked") as cli:
                        with self.assertRaises(RuntimeError):
                            applied.stop_core_with_held_tunnels(
                                "/app", {}, "/daemon.sock", 41001, node,
                                5, 9, 222)
                        opened.assert_not_called()
                        cli.assert_not_called()

        # Even with three established tunnels, PID drift immediately before
        # stop must refuse the CLI command and close all three test sockets.
        node = Node()
        opened = []
        def connect_for_drift(port, _echo_port, _payload):
            held_socket = Held()
            opened.append(held_socket)
            if port == 2082:
                node.calls += 1
            return held_socket
        with mock.patch.object(applied, "unix_json",
                               side_effect=[running, dict(running, core_pid=333)]):
            with mock.patch.object(applied, "open_held_socks_echo",
                                   side_effect=connect_for_drift):
                with mock.patch.object(applied.boot, "checked") as cli:
                    with self.assertRaises(RuntimeError):
                        applied.stop_core_with_held_tunnels(
                            "/app", {}, "/daemon.sock", 41001, node,
                            5, 9, 222)
                    cli.assert_not_called()
        self.assertEqual(len(opened), 3)
        self.assertTrue(all(c.closed for c in opened))

        for unhealthy in ("failed", "reject_connections"):
            node = Node()
            setattr(node, unhealthy, True)
            with mock.patch.object(applied, "open_held_socks_echo") as dial:
                with self.assertRaises(RuntimeError):
                    applied.stop_core_with_held_tunnels(
                        "/app", {}, "/daemon.sock", 41001, node,
                        5, 9, 222)
                dial.assert_not_called()

    def test_explicit_restart_after_held_stop_retains_generation_and_routes(self):
        class Node:
            calls = 6
            rejections = 3
            failed = False
            reject_connections = False

        node = Node()
        origin = self.synthetic_http_origin()
        state = {"running": False, "pid": 0}
        commands, payloads = [], []

        def current_status():
            doc = self.promoted_status(pid=state["pid"])
            if not state["running"]:
                doc.update({
                    "core_state": "stopped",
                    "core_desired_state": "stopped",
                    "core_pid": 0,
                })
            return doc

        def api(_sock, method, route, payload=None, expected=200, timeout=85):
            self.assertEqual(method, "GET")
            if route == "/v1/status":
                return current_status()
            if route == "/v1/declaration/current":
                return {"revision": 2, "sha256": "b" * 64}
            self.fail("unapproved endpoint")

        def command(argv, env, timeout=22):
            self.assertEqual((argv[:2], env), (["/app", "core"], {}))
            self.assertIn(argv[2], ("start", "stop"))
            commands.append(argv[2])
            if argv[2] == "start":
                self.assertFalse(state["running"])
                state.update({"running": True, "pid": 222})
            else:
                self.assertTrue(state["running"])
                state.update({"running": False, "pid": 0})
            return b""

        def wait(_app, _env, expected):
            self.assertEqual(expected, "running" if state["running"] else "stopped")
            return current_status()

        def routes(echo_port, payload, target):
            self.assertEqual((echo_port, target), (41001, node))
            node.calls += 1
            payloads.append(payload)

        def refusal(echo_port, payload, target):
            self.assertEqual((echo_port, target), (41001, node))
            self.assertEqual(payload, b"after-held-stop-failed-")
            node.rejections += 1

        opened_http = []
        def held_http_open(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            self.assertEqual(payload,
                             b"held-http-stop-" + str(port).encode())
            conn = mock.Mock()
            opened_http.append(conn)
            if port == 2082:
                node.calls += 1
            return conn

        with mock.patch.object(applied, "unix_json", side_effect=api):
            with mock.patch.object(applied.boot, "checked",
                                   side_effect=command) as cli:
                with mock.patch.object(applied, "wait_status", side_effect=wait):
                    with mock.patch.object(applied, "verify_child") as verify:
                        with mock.patch.object(applied, "probe_isolated_routes",
                                               side_effect=routes) as probe:
                            with mock.patch.object(applied, "probe_isolated_failure",
                                                   side_effect=refusal) as denied:
                                with (mock.patch.object(applied, "verify_stopped_ports") as closed,
                                      mock.patch.object(applied, "probe_bounded_reconnect_churn",
                                                        return_value=72) as churn,
                                      mock.patch.object(applied, "probe_http_route_isolation",
                                                        return_value=3) as http_route,
                                      mock.patch.object(applied, "probe_http_selected_failure_isolation",
                                                        return_value=3) as http_failure,
                                      mock.patch.object(applied, "probe_parallel_http_connects",
                                                        return_value=12) as parallel_http,
                                      mock.patch.object(applied, "probe_parallel_http_selected_denials",
                                                        return_value=12) as parallel_denials,
                                      mock.patch.object(applied, "probe_split_write_http_route_isolation",
                                                        return_value=3) as split_http,
                                      mock.patch.object(applied, "probe_http_absolute_route_isolation",
                                                        return_value=3) as absolute_http,
                                      mock.patch.object(
                                          applied, "probe_http_absolute_selected_failure_isolation",
                                          return_value=3) as absolute_denial,
                                      mock.patch.object(applied, "probe_selected_socks_domain_route",
                                                        return_value=1) as domain_probe,
                                      mock.patch.object(applied, "open_held_http_echo",
                                                        side_effect=held_http_open) as held_dial,
                                      mock.patch.object(applied, "assert_held_http_closed") as held_eof):
                                    stages = []
                                    pid = applied.probe_restart_after_held_stop(
                                        "/app", {}, "/daemon.sock", 100,
                                        "/approved-core", 5, 9,
                                        41001, node, "b" * 64,
                                        http_origin=origin,
                                        stage_hook=stages.append)
        self.assertEqual(stages, [
            "http-restart-preflight", "http-restart-core-start",
            "http-restart-socks-routes", "http-restart-socks-refusal",
            "http-restart-socks-restored", "http-restart-reconnect-fd",
            "http-restart-connect-ip", "http-restart-selected-failure",
            "http-restart-concurrent-connect",
            "http-restart-parallel-selected-refusal",
            "http-restart-parallel-selected-restored",
            "http-restart-split-header-writes",
            "http-restart-absolute-form",
            "http-restart-absolute-selected-refusal",
            "http-restart-selected-socks-domain",
            "http-restart-held-http-open", "http-restart-final-stop",
            "http-restart-held-http-close",
        ])
        self.assertEqual(pid, 222)
        self.assertEqual(commands, ["start", "stop"])
        self.assertEqual(cli.call_count, 2)
        verify.assert_called_once_with(222, 100, "/approved-core")
        churn.assert_called_once_with(
            "/daemon.sock", 100, "/approved-core", 5, 9,
            222, 41001, node)
        http_route.assert_called_once_with(
            "/daemon.sock", 5, 9, 222, 41001, node)
        http_failure.assert_called_once()
        self.assertEqual(http_failure.call_args.args,
                         ("/daemon.sock", 5, 9, 222, 41001, node))
        self.assertTrue(callable(
            http_failure.call_args.kwargs["stage_hook"]))
        self.assertEqual(parallel_http.call_count, 2)
        self.assertEqual(parallel_http.call_args_list, [
            mock.call("/daemon.sock", 5, 9, 222, 41001, node),
            mock.call("/daemon.sock", 5, 9, 222, 41001, node)])
        parallel_denials.assert_called_once_with(
            "/daemon.sock", 5, 9, 222, 41001, node)
        split_http.assert_called_once_with(
            "/daemon.sock", 5, 9, 222, 41001, node)
        absolute_http.assert_called_once_with(
            "/daemon.sock", 5, 9, 222, origin, node)
        absolute_denial.assert_called_once()
        self.assertEqual(absolute_denial.call_args.args,
                         ("/daemon.sock", 5, 9, 222, origin, node))
        self.assertTrue(callable(
            absolute_denial.call_args.kwargs["stage_hook"]))
        domain_probe.assert_called_once_with(
            "/daemon.sock", 5, 9, 222, 41001, node)
        self.assertEqual(probe.call_count, 2)
        denied.assert_called_once_with(41001, b"after-held-stop-failed-", node)
        self.assertEqual(payloads, [
            b"after-held-stop-start-", b"after-held-stop-restored-",
        ])
        self.assertEqual((node.calls, node.rejections), (9, 4))
        self.assertEqual(held_dial.call_count, 3)
        self.assertEqual(held_eof.call_args_list,
                         [mock.call(conn) for conn in opened_http])
        self.assertTrue(all(conn.close.call_count == 1
                            for conn in opened_http))
        self.assertEqual(closed.call_count, 2)
        self.assertFalse(state["running"])

    def test_held_stop_restart_refuses_implicit_start_or_wrong_declaration(self):
        stopped = self.promoted_status(pid=0)
        stopped.update({"core_state": "stopped", "core_desired_state": "stopped"})
        running = self.promoted_status(pid=222)
        for name, first, sha in (
            ("implicitly-running", running, "b" * 64),
            ("wrong-config", dict(stopped, config_revision=1), "b" * 64),
            ("wrong-LKG", dict(stopped, last_known_good_generation_id=5),
             "b" * 64),
            ("wrong-declaration", stopped, "c" * 64),
        ):
            with self.subTest(name=name):
                def api(_sock, _method, route, payload=None,
                        expected=200, timeout=85):
                    if route == "/v1/status":
                        return first
                    if route == "/v1/declaration/current":
                        return {"revision": 2, "sha256": sha}
                    raise AssertionError("unapproved request")
                with mock.patch.object(applied, "unix_json", side_effect=api):
                    with mock.patch.object(applied.boot, "checked") as cli:
                        with mock.patch.object(applied, "verify_stopped_ports"):
                            with self.assertRaises(RuntimeError):
                                applied.probe_restart_after_held_stop(
                                    "/app", {}, "/daemon.sock", 100,
                                    "/approved-core", 5, 9,
                                    41001, type('Node', (), {'calls': 1, 'rejections': 1, 'failed': False, 'reject_connections': False})(), "b" * 64,
                                    http_origin=self.synthetic_http_origin())
                        cli.assert_not_called()

    def test_held_stop_restart_still_stops_on_reprobe_failure(self):
        class Node:
            calls = 1
            rejections = 1
            failed = False
            reject_connections = False
        node = Node()
        state = {"running": False}
        actions = []

        def status():
            doc = self.promoted_status(pid=222 if state["running"] else 0)
            if not state["running"]:
                doc.update({"core_state": "stopped",
                            "core_desired_state": "stopped"})
            return doc

        def api(_sock, method, route, payload=None, expected=200, timeout=85):
            if route == "/v1/status":
                return status()
            if route == "/v1/declaration/current":
                return {"sha256": "b" * 64}
            raise AssertionError("unapproved API")
        def cli(argv, env, timeout=22):
            actions.append(argv[2])
            state["running"] = argv[2] == "start"
            return b""
        def wait(_app, _env, _expected):
            return status()

        with mock.patch.object(applied, "unix_json", side_effect=api):
            with mock.patch.object(applied.boot, "checked", side_effect=cli):
                with mock.patch.object(applied, "wait_status", side_effect=wait):
                    with mock.patch.object(applied, "verify_child"):
                        with mock.patch.object(applied, "verify_stopped_ports") as closed:
                            with mock.patch.object(applied, "probe_isolated_routes",
                                                   side_effect=RuntimeError("echo failed")):
                                with self.assertRaises(RuntimeError):
                                    applied.probe_restart_after_held_stop(
                                        "/app", {}, "/daemon.sock", 100,
                                        "/approved-core", 5, 9,
                                        41001, node, "b" * 64,
                                         http_origin=self.synthetic_http_origin())
        self.assertEqual(actions, ["start", "stop"])
        self.assertFalse(state["running"])
        self.assertEqual(closed.call_count, 2)


    def test_bounded_reconnect_three_inbounds_and_owned_fd_settle(self):
        class Node:
            calls = 5
            rejections = 2
            parallel_payloads = []
            failed = False
            reject_connections = False

        node = Node()
        payloads = []
        def routes(echo_port, prefix, target):
            self.assertEqual((echo_port, target), (41001, node))
            payloads.append(prefix)
            node.calls += 1

        with mock.patch.object(applied, "unix_json",
                               return_value=self.promoted_status(pid=222)) as api:
            with mock.patch.object(applied, "verify_child") as child:
                # Daemon before, pinned Core before, Daemon after, Core after.
                with mock.patch.object(applied, "daemon_fd_count",
                                       side_effect=[12, 18, 15, 20]) as fd:
                    with mock.patch.object(applied, "probe_isolated_routes",
                                           side_effect=routes) as probe:
                        total = applied.probe_bounded_reconnect_churn(
                            "/daemon.sock", 100, "/approved-core",
                            5, 9, 222, 41001, node, cycles=3)
        self.assertEqual(total, 9)
        self.assertEqual(payloads,
                         [b"reconnect-00-", b"reconnect-01-", b"reconnect-02-"])
        self.assertEqual((node.calls, node.rejections), (8, 2))
        self.assertEqual(api.call_count, 2)
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(fd.call_args_list, [
            mock.call(100), mock.call(222), mock.call(100), mock.call(222)])
        self.assertEqual(child.call_args_list, [
            mock.call(222, 100, "/approved-core"),
            mock.call(222, 100, "/approved-core")])

    def test_reconnect_fd_budget_requires_bounded_numeric_samples(self):
        self.assertTrue(applied.reconnect_fd_budget(12, 20, 28, 44))
        self.assertTrue(applied.reconnect_fd_budget(12, 20, 8, 19))
        self.assertFalse(applied.reconnect_fd_budget(12, 20, 29, 44))
        self.assertFalse(applied.reconnect_fd_budget(12, 20, 28, 45))
        for samples in ((True, 20, 28, 44), (0, 20, 28, 44),
                        (12, -1, 28, 44), (12, 20, 1024, 44),
                        (12, 20, 28, 2.3)):
            with self.subTest(samples=samples):
                with self.assertRaises(RuntimeError):
                    applied.reconnect_fd_budget(*samples)

    def test_reconnect_churn_refuses_pid_drift_selected_bypass_and_fd_leak(self):
        class Node:
            calls = 0
            rejections = 0
            parallel_payloads = []
            failed = False
            reject_connections = False

        arguments = ("/daemon.sock", 100, "/approved-core",
                     5, 9, 222, 41001)
        for cycles in (0, -1, 25, True, 1.5):
            with self.subTest(invalid_cycles=cycles):
                with mock.patch.object(applied, "unix_json") as api:
                    with self.assertRaises(RuntimeError):
                        applied.probe_bounded_reconnect_churn(
                            *arguments, Node(), cycles=cycles)
                    api.assert_not_called()

        for unhealthy in ("failed", "reject_connections"):
            node = Node()
            setattr(node, unhealthy, True)
            with mock.patch.object(applied, "unix_json") as api:
                with self.assertRaises(RuntimeError):
                    applied.probe_bounded_reconnect_churn(
                        *arguments, node, cycles=1)
                api.assert_not_called()

        good = self.promoted_status(pid=222)
        drifted = self.promoted_status(pid=333)
        for defect in ("stale-start", "mid-churn-pid", "selected-bypass",
                       "unexpected-refusal", "core-fd-leak"):
            with self.subTest(defect=defect):
                node = Node()
                def routes(_echo, _prefix, target):
                    self.assertIs(target, node)
                    if defect != "selected-bypass":
                        node.calls += 1
                    if defect == "unexpected-refusal":
                        node.rejections += 1
                statuses = ([drifted] if defect == "stale-start"
                            else [good, drifted] if defect == "mid-churn-pid"
                            else [good, good])
                with mock.patch.object(applied, "unix_json",
                                       side_effect=statuses):
                    with mock.patch.object(applied, "verify_child"):
                        fd_counts = ([12, 20, 50, 60]
                                     if defect == "core-fd-leak"
                                     else [12, 20, 12, 20])
                        with mock.patch.object(applied, "daemon_fd_count",
                                               side_effect=fd_counts) as fd:
                            with mock.patch.object(applied, "probe_isolated_routes",
                                                   side_effect=routes) as probe:
                                with mock.patch.object(applied.time, "monotonic",
                                                       side_effect=[0, 5]):
                                    with self.assertRaises(RuntimeError):
                                        applied.probe_bounded_reconnect_churn(
                                            *arguments, node, cycles=1)
                if defect == "stale-start":
                    fd.assert_not_called()
                    probe.assert_not_called()


    def test_open_held_http_echo_retains_live_socket_and_cleans_failures(self):
        class Conn:
            def __init__(self, response):
                self.pending = bytearray(response)
                self.closed = False
                self.writes = []
                self.timeouts = []
            def settimeout(self, value):
                self.timeouts.append(value)
            def sendall(self, payload):
                self.writes.append(payload)
            def recv(self, size):
                n = min(size, len(self.pending))
                chunk = bytes(self.pending[:n])
                del self.pending[:n]
                return chunk
            def close(self):
                self.closed = True

        payload = b"held-http-stop-2082"
        for port in applied.MANAGED_PORTS:
            with self.subTest(port=port):
                response = (b"HTTP/1.1 200 Connection established\r\n"
                            b"Via: local-test\r\n\r\n" +
                            loopback.REPLY_PREFIX + payload)
                conn = Conn(response)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as dial:
                    self.assertIs(
                        applied.open_held_http_echo(port, 41001, payload), conn)
                dial.assert_called_once_with(("127.0.0.1", port), timeout=4)
                self.assertFalse(conn.closed)
                self.assertEqual(conn.timeouts, [4])
                self.assertEqual(conn.writes, [
                    b"CONNECT 127.0.0.1:41001 HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:41001\r\n\r\n", payload
                ])
                conn.close()
                self.assertTrue(conn.closed)

        for reply in (
            b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
            b"HTTP/1.1 200 Connection established\r\n",
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 1050,
            b"INVALID 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nbad-echo",
        ):
            with self.subTest(reply=reply[:30]):
                conn = Conn(reply)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises(RuntimeError):
                        applied.open_held_http_echo(2082, 41001, payload)
                self.assertTrue(conn.closed)
        for port, echo, message in (
            (2089, 41001, payload), (True, 41001, payload),
            (2082, True, payload), (2082, 65536, payload),
            (2082, 41001, b""), (2082, 41001, "not-bytes"),
            (2082, 41001, b"x" * 129),
        ):
            with self.subTest(bad_port=port, bad_echo=echo):
                with mock.patch.object(applied.socket, "create_connection") as dial:
                    with self.assertRaises(RuntimeError):
                        applied.open_held_http_echo(port, echo, message)
                    dial.assert_not_called()

    def test_held_http_must_eof_or_reset_after_explicit_core_stop(self):
        for observed in (b"", ConnectionResetError("reset"),
                         ConnectionAbortedError("abort"), BrokenPipeError("pipe")):
            conn = mock.Mock()
            if isinstance(observed, bytes):
                conn.recv.return_value = observed
            else:
                conn.recv.side_effect = observed
            applied.assert_held_http_closed(conn)
            conn.settimeout.assert_called_once_with(3)
            conn.recv.assert_called_once_with(1)
        for observed in (b"private data", socket.timeout("still alive")):
            conn = mock.Mock()
            if isinstance(observed, bytes):
                conn.recv.return_value = observed
            else:
                conn.recv.side_effect = observed
            with self.assertRaises((RuntimeError, socket.timeout)):
                applied.assert_held_http_closed(conn)
        self.assertEqual(applied.safe_airgap_failure_code(RuntimeError(
            "stopped Core forwarded data on held HTTP CONNECT tunnel")),
            "held-http-still-forwarding")
        self.assertEqual(applied.safe_airgap_failure_code(RuntimeError(
            "held HTTP CONNECT crossed Selected or bypassed its node")),
            "held-http-route-bypass")
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("HTTP CONNECT private token abc")), "unclassified")


    def test_split_write_http_connect_sends_exact_separate_writes_and_echo(self):
        class Conn:
            def __init__(self, response):
                self.buffer = bytearray(response)
                self.writes = []
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_unused):
                self.closed = True
            def settimeout(self, n):
                self.timeout = n
            def sendall(self, data):
                self.writes.append(data)
            def recv(self, n):
                k = min(n, len(self.buffer))
                part = bytes(self.buffer[:k])
                del self.buffer[:k]
                return part

        for port in applied.MANAGED_PORTS:
            with self.subTest(port=port):
                payload = b"split-http-connect-" + str(port).encode()
                response = (b"HTTP/1.1 200 Connection established\r\n"
                            b"Proxy: synthetic\r\n\r\n" +
                            loopback.REPLY_PREFIX + payload)
                conn = Conn(response)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as dial:
                    applied.probe_split_write_http_connect_ip(
                        port, 41001, payload)
                dial.assert_called_once_with(("127.0.0.1", port), timeout=4)
                self.assertEqual(conn.timeout, 4)
                self.assertTrue(conn.closed)
                pieces = conn.writes[:-1]
                self.assertEqual(len(pieces), 6)
                self.assertEqual(b"".join(pieces),
                                 b"CONNECT 127.0.0.1:41001 HTTP/1.1\r\n"
                                 b"Host: 127.0.0.1:41001\r\n\r\n")
                self.assertEqual(conn.writes[-1], payload)

        payload = b"split-echo"
        for response in (
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 1100,
            b"NOTHTTP 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nwrong-data",
        ):
            with self.subTest(response=response[:30]):
                conn = Conn(response)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises(RuntimeError):
                        applied.probe_split_write_http_connect_ip(
                            2082, 41001, payload)
                self.assertTrue(conn.closed)
        for port, echo, payload in (
            (True, 41001, b"x"), (2089, 41001, b"x"),
            (2082, True, b"x"), (2082, 0, b"x"),
            (2082, 65536, b"x"), (2082, 41001, ""),
            (2082, 41001, b""), (2082, 41001, b"x" * 129),
        ):
            with self.subTest(port=port, echo=echo):
                with mock.patch.object(applied.socket, "create_connection") as dial:
                    with self.assertRaises(RuntimeError):
                        applied.probe_split_write_http_connect_ip(
                            port, echo, payload)
                    dial.assert_not_called()

    def test_split_write_http_route_only_selected_and_no_core_change(self):
        class Node:
            calls = 17
            rejections = 5
            failed = False
            reject_connections = False

        node = Node()
        good = self.promoted_status(pid=222)
        seen = []
        def dial(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            self.assertEqual(payload,
                             b"split-http-connect-" + str(port).encode())
            seen.append(port)
            if port == 2082:
                node.calls += 1
        with mock.patch.object(applied, "unix_json", return_value=good) as api:
            with mock.patch.object(applied, "probe_split_write_http_connect_ip",
                                   side_effect=dial) as called:
                self.assertEqual(
                    applied.probe_split_write_http_route_isolation(
                        "/sock", 5, 9, 222, 41001, node), 3)
        self.assertEqual(seen, list(applied.MANAGED_PORTS))
        self.assertEqual((node.calls, node.rejections), (18, 5))
        self.assertEqual(api.call_count, 2)
        self.assertEqual(called.call_count, 3)

        bad_pid = self.promoted_status(pid=333)
        for defect in ("wrong-start", "rule-cross", "selected-bypass",
                       "new-rejection", "changed-core"):
            with self.subTest(defect=defect):
                node = Node()
                node.calls = 17
                node.rejections = 5
                def corrupt(port, _echo, _payload):
                    if port == 2080 and defect == "rule-cross":
                        node.calls += 1
                    if port == 2082 and defect != "selected-bypass":
                        node.calls += 1
                    if port == 2080 and defect == "new-rejection":
                        node.rejections += 1
                states = ([bad_pid] if defect == "wrong-start" else
                          [good, bad_pid] if defect == "changed-core" else
                          [good, good])
                with mock.patch.object(applied, "unix_json",
                                       side_effect=states):
                    with mock.patch.object(applied, "probe_split_write_http_connect_ip",
                                           side_effect=corrupt) as called:
                        with self.assertRaises(RuntimeError):
                            applied.probe_split_write_http_route_isolation(
                                "/sock", 5, 9, 222, 41001, node)
                        if defect == "wrong-start":
                            called.assert_not_called()
        self.assertEqual(
            applied.safe_airgap_failure_code(RuntimeError(
                "split-write HTTP CONNECT crossed or skipped Selected")),
            "split-http-route-bypass")
        self.assertEqual(
            applied.safe_airgap_failure_code(RuntimeError(
                "private DNS or secret should not be logged")),
            "unclassified")

    def test_http_absolute_selected_refusal_only_accepts_bounded_failure(self):
        class Conn:
            def __init__(self, response=b"", error=None, send_error=None):
                self.buffer = bytearray(response)
                self.error = error
                self.send_error = send_error
                self.writes = []
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True
            def settimeout(self, n):
                self.timeout = n
            def sendall(self, data):
                self.writes.append(data)
                if self.send_error is not None:
                    raise self.send_error
            def recv(self, n):
                if self.buffer:
                    chunk = bytes(self.buffer[:n])
                    del self.buffer[:n]
                    return chunk
                if self.error is not None:
                    raise self.error
                return b""

        request = (
            b"GET http://127.0.0.1:41002/t24-http-absolute-2082 HTTP/1.1\r\n"
            b"Host: 127.0.0.1:41002\r\nConnection: close\r\n\r\n")
        valid = (
            (b"", None, None),
            (b"", ConnectionResetError("reset"), None),
            (b"", ConnectionAbortedError("abort"), None),
            (b"", None, BrokenPipeError("early-close")),
            (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", None, None),
            (b"HTTP/1.0 403 Forbidden\r\n\r\n", None, None),
            (b"HTTP/1.1 500 Internal Server Error\r\n"
             b"Connection: close\r\n\r\n", None, None),
        )
        for response, error, send_error in valid:
            with self.subTest(valid=response[:20], error=type(error).__name__):
                conn = Conn(response, error, send_error)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as dial:
                    applied.probe_http_absolute_selected_refusal(41002)
                dial.assert_called_once_with(("127.0.0.1", 2082), timeout=4)
                self.assertEqual(conn.timeout, 4)
                self.assertEqual(conn.writes, [request])
                self.assertTrue(conn.closed)
        invalid = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\n\r\n",
            b"HTTP/1.1 302 Found\r\n\r\n",
            b"HTTP/1.1 600 Bad\r\n\r\n",
            b"HTTP/1.1 502 Bad Gateway\r\n",
            b"HTTP/1.1 502 Bad Gateway\r\nX: " + b"x" * 1100,
            b"BROKEN 502 Bad Gateway\r\n\r\n",
            b"HTTP/1.1 502 Bad Gateway\r\nMalformed\r\n\r\n",
        )
        for response in invalid:
            with self.subTest(invalid=response[:25]):
                conn = Conn(response)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_absolute_selected_refusal(41002)
                self.assertTrue(conn.closed)
        for error in (ConnectionResetError("partial"), socket.timeout("hang")):
            with self.subTest(error=type(error).__name__):
                conn = Conn(b"HTTP/1.1 502", error=error)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises((RuntimeError, socket.timeout)):
                        applied.probe_http_absolute_selected_refusal(41002)
                self.assertTrue(conn.closed)
        with mock.patch.object(applied.socket, "create_connection",
                               return_value=Conn(error=socket.timeout("hang"))):
            with self.assertRaises(socket.timeout):
                applied.probe_http_absolute_selected_refusal(41002)
        for bad in (0, True, 65536, "41002", 41002.5):
            with mock.patch.object(applied.socket, "create_connection") as dial:
                with self.assertRaises(RuntimeError):
                    applied.probe_http_absolute_selected_refusal(bad)
                dial.assert_not_called()

    def test_http_absolute_selected_refusal_isolates_origin_and_recovers(self):
        class Node:
            calls = 8
            rejections = 3
            failed = False
            reject_connections = False

        node = Node()
        origin = self.synthetic_http_origin()
        visited = []
        def origin_get(port, origin_port):
            self.assertEqual(origin_port, 41002)
            visited.append((port, node.reject_connections))
            path = "/t24-http-absolute-" + str(port)
            with origin.counter_lock:
                origin.receipts.append((
                    path, "127.0.0.1:41002", "GET " + path + " HTTP/1.1"))
            if port == 2082:
                self.assertFalse(node.reject_connections)
                node.calls += 1
        def refused(port):
            self.assertEqual(port, 41002)
            self.assertTrue(node.reject_connections)
            self.assertEqual(visited, [(2080, True), (2081, True)])
            node.rejections += 1
        def restored(_sock, _old, _new, _pid, observed_origin, observed_node):
            self.assertFalse(node.reject_connections)
            self.assertIs(observed_origin, origin)
            self.assertIs(observed_node, node)
            for port in applied.MANAGED_PORTS:
                origin_get(port, 41002)
            return 3
        with (mock.patch.object(applied, "unix_json",
                                return_value=self.promoted_status(pid=222)) as api,
              mock.patch.object(applied, "probe_http_absolute_form_get",
                                side_effect=origin_get) as get,
              mock.patch.object(applied, "probe_http_absolute_selected_refusal",
                                side_effect=refused) as selected,
              mock.patch.object(applied, "probe_http_absolute_route_isolation",
                                side_effect=restored) as recovery):
            stages = []
            result = applied.probe_http_absolute_selected_failure_isolation(
                "/sock", 5, 9, 222, origin, node, stage_hook=stages.append)
        self.assertEqual(result, 3)
        self.assertEqual(stages, [
            "absolute-failure-preflight", "absolute-failure-rule",
            "absolute-failure-direct", "absolute-failure-selected",
            "absolute-failure-denial-audit", "absolute-failure-pid-after-restore",
            "absolute-failure-recovery", "absolute-failure-final-audit",
        ])
        self.assertEqual(visited, [
            (2080, True), (2081, True),
            (2080, False), (2081, False), (2082, False),
        ])
        self.assertEqual((node.calls, node.rejections), (9, 4))
        self.assertFalse(node.failed)
        self.assertFalse(node.reject_connections)
        self.assertEqual(len(origin.receipts), 5)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(get.call_count, 2)
        selected.assert_called_once_with(41002)
        recovery.assert_called_once_with("/sock", 5, 9, 222, origin, node)

    def test_http_absolute_selected_failure_rejects_bypass_and_resets_toggle(self):
        class Node:
            def __init__(self):
                self.calls = 8
                self.rejections = 3
                self.failed = False
                self.reject_connections = False

        good = self.promoted_status(pid=222)
        wrong = self.promoted_status(pid=333)
        for defect in (
            "stale-core", "rule-cross", "missing-origin", "duplicate-origin",
            "selected-origin-leak", "selected-bypass", "denial-storm",
            "selected-accepted", "bad-selected-response", "changed-core",
            "missing-recovery", "extra-recovery-node", "extra-recovery-origin",
        ):
            with self.subTest(defect=defect):
                node = Node()
                origin = self.synthetic_http_origin()
                def append_receipt(port):
                    path = "/t24-http-absolute-" + str(port)
                    with origin.counter_lock:
                        origin.receipts.append((
                            path, "127.0.0.1:41002",
                            "GET " + path + " HTTP/1.1"))
                def healthy(port, origin_port):
                    self.assertEqual(origin_port, 41002)
                    if defect != "missing-origin" or port != 2080:
                        append_receipt(port)
                    if defect == "duplicate-origin" and port == 2080:
                        append_receipt(port)
                    if defect == "rule-cross" and port == 2080:
                        node.calls += 1
                def refusal(_origin_port):
                    self.assertTrue(node.reject_connections)
                    if defect == "selected-origin-leak":
                        append_receipt(2082)
                    if defect == "selected-accepted":
                        node.calls += 1
                    if defect not in ("selected-bypass",):
                        node.rejections += 5 if defect == "denial-storm" else 1
                    if defect == "bad-selected-response":
                        raise RuntimeError(
                            "HTTP absolute-form Selected returned unsafe response")
                def recovery(*_args):
                    self.assertFalse(node.reject_connections)
                    for port in applied.MANAGED_PORTS:
                        append_receipt(port)
                    node.calls += 2 if defect == "extra-recovery-node" else 1
                    if defect == "extra-recovery-origin":
                        append_receipt(2082)
                    return 2 if defect == "missing-recovery" else 3
                statuses = ([wrong] if defect == "stale-core" else
                            [good, wrong] if defect == "changed-core" else
                            [good, good])
                with (mock.patch.object(applied, "unix_json",
                                        side_effect=statuses),
                      mock.patch.object(applied, "probe_http_absolute_form_get",
                                        side_effect=healthy) as get,
                      mock.patch.object(applied, "probe_http_absolute_selected_refusal",
                                        side_effect=refusal),
                      mock.patch.object(applied, "probe_http_absolute_route_isolation",
                                        side_effect=recovery)):
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_absolute_selected_failure_isolation(
                            "/sock", 5, 9, 222, origin, node)
                self.assertFalse(node.reject_connections)
                if defect == "stale-core":
                    get.assert_not_called()

        for defect in ("invalid-origin", "invalid-node", "bad-hook"):
            with self.subTest(fixture=defect):
                origin = self.synthetic_http_origin()
                node = Node()
                hook = None
                if defect == "invalid-origin":
                    origin.server_address = ("8.8.8.8", 53)
                elif defect == "invalid-node":
                    node.failed = True
                else:
                    hook = "untrusted callback"
                with mock.patch.object(applied, "unix_json") as api:
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_absolute_selected_failure_isolation(
                            "/sock", 5, 9, 222, origin, node, stage_hook=hook)
                    api.assert_not_called()
                self.assertFalse(node.reject_connections)

        for reason, code in (
            ("HTTP absolute-form Selected returned unsafe response",
             "http-absolute-denial-unsafe"),
            ("HTTP absolute-form rejected Selected reached origin",
             "http-absolute-leak"),
            ("HTTP absolute-form Rule/Direct reached Selected",
             "http-absolute-healthy-route"),
            ("HTTP absolute-form Selected denial unobserved or bypassed",
             "http-absolute-denial-bypass"),
            ("HTTP absolute-form failure recovered routes drifted",
             "http-absolute-denial-final"),
        ):
            self.assertEqual(
                applied.safe_airgap_failure_code(RuntimeError(reason)), code)
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("private URL token not for logging")), "unclassified")

    def test_selected_domain_client_exact_atyp3_and_strict_echo(self):
        class Conn:
            def __init__(self, answer):
                self.buffer = bytearray(answer)
                self.sent = []
                self.closed = False
                self.timeout = None
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True
            def settimeout(self, n):
                self.timeout = n
            def sendall(self, data):
                self.sent.append(data)
            def recv(self, n):
                count = min(n, len(self.buffer))
                result = bytes(self.buffer[:count])
                del self.buffer[:count]
                return result

        host = applied.SOCKS_DOMAIN_TARGET
        payload = b"domain-echo-fixture"
        request = (b"\x05\x01\x00\x03" + bytes([len(host)]) + host +
                   struct.pack("!H", 41001))
        replies = (
            b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
            struct.pack("!H", 41001),
            b"\x05\x00\x00\x03\x01x" + struct.pack("!H", 41001),
            b"\x05\x00\x00\x04" + b"\x00" * 16 +
            struct.pack("!H", 41001),
        )
        for reply in replies:
            with self.subTest(atyp=reply[3]):
                conn = Conn(b"\x05\x00" + reply + loopback.REPLY_PREFIX + payload)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as dial:
                    applied.probe_selected_socks_domain(41001, payload)
                dial.assert_called_once_with(("127.0.0.1", 2082), timeout=4)
                self.assertEqual(conn.sent, [
                    b"\x05\x01\x00", request, payload,
                ])
                self.assertEqual(conn.timeout, 4)
                self.assertTrue(conn.closed)

        invalid_answers = (
            b"\x05\xff",
            b"\x05\x00" + b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00",
            b"\x05\x00" + b"\x05\x00\x00\x09",
            b"\x05\x00" + b"\x05\x00\x00\x03\x00",
            b"\x05\x00" + b"\x05\x00\x00\x01",
            b"\x05\x00" + replies[0] + b"incorrect-echo-data",
            b"\x05\x00" + replies[0] + loopback.REPLY_PREFIX,
        )
        for response in invalid_answers:
            with self.subTest(bad_response=response[:12]):
                conn = Conn(response)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises(RuntimeError):
                        applied.probe_selected_socks_domain(41001, payload)
                self.assertTrue(conn.closed)
        for port, body in (
            (True, b"x"), (0, b"x"), (65536, b"x"),
            (41001, b""), (41001, b"x" * 129), (41001, "secret"),
        ):
            with self.subTest(port=port, payload_type=type(body).__name__):
                with mock.patch.object(applied.socket, "create_connection") as dial:
                    with self.assertRaises(RuntimeError):
                        applied.probe_selected_socks_domain(port, body)
                    dial.assert_not_called()

    def test_selected_domain_route_requires_exact_upstream_receipt_and_pid(self):
        class Node:
            def __init__(self):
                self.calls = 8
                self.rejections = 3
                self.failed = False
                self.reject_connections = False
                self.hostname_requests = []
                self.counter_lock = threading.Lock()

        node = Node()
        good = self.promoted_status(pid=222)
        def successful(port, payload):
            self.assertEqual((port, payload),
                             (41001, b"selected-domain-only-echo"))
            node.calls += 1
            with node.counter_lock:
                node.hostname_requests.append(
                    (applied.SOCKS_DOMAIN_TARGET, port))
        with (mock.patch.object(applied, "unix_json", return_value=good) as api,
              mock.patch.object(applied, "probe_selected_socks_domain",
                                side_effect=successful) as probe):
            result = applied.probe_selected_socks_domain_route(
                "/sock", 5, 9, 222, 41001, node)
        self.assertEqual(result, 1)
        self.assertEqual((node.calls, node.rejections), (9, 3))
        self.assertEqual(node.hostname_requests,
                         [(applied.SOCKS_DOMAIN_TARGET, 41001)])
        self.assertEqual(api.call_count, 2)
        probe.assert_called_once_with(41001, b"selected-domain-only-echo")

        for defect in ("stale-pid", "missing-receipt", "wrong-receipt",
                       "duplicate-receipt", "upstream-bypass", "new-refusal",
                       "node-failed", "pid-replaced"):
            with self.subTest(defect=defect):
                node = Node()
                changed = self.promoted_status(pid=333)
                statuses = ([changed] if defect == "stale-pid" else
                            [good, changed] if defect == "pid-replaced" else
                            [good, good])
                def corrupted(port, _payload):
                    if defect not in ("upstream-bypass",):
                        node.calls += 1
                    if defect == "node-failed":
                        node.failed = True
                    if defect == "new-refusal":
                        node.rejections += 1
                    if defect != "missing-receipt":
                        with node.counter_lock:
                            domain = (b"incorrect.invalid" if
                                      defect == "wrong-receipt" else
                                      applied.SOCKS_DOMAIN_TARGET)
                            node.hostname_requests.append((domain, port))
                            if defect == "duplicate-receipt":
                                node.hostname_requests.append((domain, port))
                with (mock.patch.object(applied, "unix_json",
                                        side_effect=statuses),
                      mock.patch.object(applied, "probe_selected_socks_domain",
                                        side_effect=corrupted) as dial):
                    with self.assertRaises(RuntimeError):
                        applied.probe_selected_socks_domain_route(
                            "/sock", 5, 9, 222, 41001, node)
                    if defect == "stale-pid":
                        dial.assert_not_called()

        invalid = Node()
        invalid.hostname_requests = None
        with mock.patch.object(applied, "unix_json") as api:
            with self.assertRaises(RuntimeError):
                applied.probe_selected_socks_domain_route(
                    "/sock", 5, 9, 222, 41001, invalid)
            api.assert_not_called()
        for error, code in (
            ("invalid selected SOCKS domain route fixture",
             "socks-domain-route-invalid"),
            ("selected SOCKS domain bypassed exact upstream hostname",
             "socks-domain-bypass"),
            ("selected SOCKS domain began on changed Core",
             "socks-domain-stale"),
            ("selected SOCKS domain echo did not match", "socks-domain-echo"),
        ):
            self.assertEqual(
                applied.safe_airgap_failure_code(RuntimeError(error)), code)
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("private DNS token")), "unclassified")

    def test_http_absolute_form_client_exact_request_response_and_fail_close(self):
        class Conn:
            def __init__(self, answer):
                self.buffer = bytearray(answer)
                self.writes = []
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True
            def settimeout(self, n):
                self.timeout = n
            def sendall(self, data):
                self.writes.append(data)
            def recv(self, n):
                take = min(n, len(self.buffer))
                result = bytes(self.buffer[:take])
                del self.buffer[:take]
                return result

        for port in applied.MANAGED_PORTS:
            with self.subTest(port=port):
                path = b"/t24-http-absolute-" + str(port).encode()
                body = b"T24-ABS-ORIGIN:" + path
                answer = (b"HTTP/1.1 200 OK\r\nContent-Length: " +
                          str(len(body)).encode() +
                          b"\r\nConnection: close\r\n\r\n" + body)
                conn = Conn(answer)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as dial:
                    applied.probe_http_absolute_form_get(port, 41002)
                self.assertTrue(conn.closed)
                self.assertEqual(conn.timeout, 4)
                dial.assert_called_once_with(("127.0.0.1", port), timeout=4)
                self.assertEqual(conn.writes, [
                    b"GET http://127.0.0.1:41002" + path + b" HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:41002\r\nConnection: close\r\n\r\n",
                ])

        good_path = b"/t24-http-absolute-2082"
        good_body = b"T24-ABS-ORIGIN:" + good_path
        for answer in (
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 1100,
            b"NOTHTTP 200 OK\r\nContent-Length: 4\r\n\r\ntest",
            b"HTTP/1.1 200 OK\r\nMalformed\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b"Content-Length: 4\r\n\r\ntest",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nContent-Length: " +
            str(len(good_body)).encode() + b"\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: " +
            str(len(good_body)).encode() + b"\r\n\r\n" +
            b"x" * len(good_body),
        ):
            with self.subTest(answer=answer[:32]):
                conn = Conn(answer)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_absolute_form_get(2082, 41002)
                self.assertTrue(conn.closed)
        for port, origin in ((True, 41002), (2089, 41002),
                             (2080, True), (2080, 0), (2080, 65536)):
            with self.subTest(bad_port=port, origin=origin):
                with mock.patch.object(applied.socket, "create_connection") as dial:
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_absolute_form_get(port, origin)
                    dial.assert_not_called()

    def test_http_absolute_form_origin_only_accepts_expected_origin_form(self):
        with applied.LocalHTTPOriginServer(
                ("127.0.0.1", 0), applied.LocalHTTPOrigin) as origin:
            thread = threading.Thread(target=origin.serve_forever, daemon=True)
            thread.start()
            try:
                host = b"127.0.0.1:" + str(origin.server_address[1]).encode()
                def query(target, header_host):
                    request = (b"GET " + target + b" HTTP/1.1\r\n" +
                               b"Host: " + header_host +
                               b"\r\nConnection: close\r\n\r\n")
                    with socket.create_connection(origin.server_address,
                                                  timeout=3) as conn:
                        conn.settimeout(3)
                        conn.sendall(request)
                        answer = bytearray()
                        while True:
                            part = conn.recv(1024)
                            if not part:
                                break
                            answer.extend(part)
                            self.assertLessEqual(len(answer), 2048)
                        return bytes(answer)
                path = b"/t24-http-absolute-2081"
                self.assertIn(b"HTTP/1.1 200", query(path, host))
                self.assertEqual(origin.receipts, [
                    (path.decode(), host.decode(),
                     "GET " + path.decode() + " HTTP/1.1"),
                ])
                self.assertIn(b" 400 ", query(
                    b"http://" + host + path, host))
                self.assertIn(b" 400 ", query(path, b"8.8.8.8"))
                self.assertEqual(len(origin.receipts), 1)
            finally:
                origin.shutdown()
                thread.join(timeout=4)

    def test_http_absolute_form_origin_and_selected_must_both_be_observed(self):
        class Node:
            def __init__(self):
                self.calls = 8
                self.rejections = 3
                self.failed = False
                self.reject_connections = False

        good = self.promoted_status(pid=222)
        origin = self.synthetic_http_origin()
        node = Node()
        visited = []
        def receive(port, origin_port):
            self.assertEqual(origin_port, 41002)
            visited.append(port)
            path = "/t24-http-absolute-" + str(port)
            with origin.counter_lock:
                origin.receipts.append((
                    path, "127.0.0.1:41002", "GET " + path + " HTTP/1.1"))
            if port == 2082:
                node.calls += 1
        with mock.patch.object(applied, "unix_json", return_value=good) as api:
            with mock.patch.object(applied, "probe_http_absolute_form_get",
                                   side_effect=receive) as dial:
                self.assertEqual(applied.probe_http_absolute_route_isolation(
                    "/sock", 5, 9, 222, origin, node), 3)
        self.assertEqual(visited, list(applied.MANAGED_PORTS))
        self.assertEqual((node.calls, node.rejections), (9, 3))
        self.assertEqual(api.call_count, 2)
        self.assertEqual(dial.call_count, 3)

        for defect in ("wrong-core", "origin-bypass", "duplicate-origin",
                       "rule-cross", "selected-bypass", "new-rejection",
                       "changed-core"):
            with self.subTest(defect=defect):
                origin = self.synthetic_http_origin()
                node = Node()
                def broken(port, _origin):
                    path = "/t24-http-absolute-" + str(port)
                    if defect != "origin-bypass":
                        with origin.counter_lock:
                            origin.receipts.append((
                                path, "127.0.0.1:41002",
                                "GET " + path + " HTTP/1.1"))
                            if defect == "duplicate-origin":
                                origin.receipts.append(origin.receipts[-1])
                    if port == 2082 and defect != "selected-bypass":
                        node.calls += 1
                    if port == 2080 and defect == "rule-cross":
                        node.calls += 1
                    if port == 2080 and defect == "new-rejection":
                        node.rejections += 1
                changed = self.promoted_status(pid=333)
                states = ([changed] if defect == "wrong-core" else
                          [good, changed] if defect == "changed-core" else
                          [good, good])
                with mock.patch.object(applied, "unix_json",
                                       side_effect=states):
                    with mock.patch.object(applied, "probe_http_absolute_form_get",
                                           side_effect=broken) as dial:
                        with self.assertRaises(RuntimeError):
                            applied.probe_http_absolute_route_isolation(
                                "/sock", 5, 9, 222, origin, node)
                        if defect == "wrong-core":
                            dial.assert_not_called()
        invalid = self.synthetic_http_origin()
        invalid.server_address = ("8.8.8.8", 53)
        with mock.patch.object(applied, "unix_json") as api:
            with self.assertRaises(RuntimeError):
                applied.probe_http_absolute_route_isolation(
                    "/sock", 5, 9, 222, invalid, Node())
            api.assert_not_called()
        for message, expected in (
            ("invalid HTTP absolute-form fixture", "http-absolute-invalid"),
            ("HTTP absolute-form crossed or skipped Selected",
             "http-absolute-route-bypass"),
            ("HTTP absolute-form did not reach approved origin exactly",
             "http-absolute-origin-bypass"),
            ("HTTP absolute-form response body incomplete",
             "http-absolute-truncated"),
        ):
            self.assertEqual(applied.safe_airgap_failure_code(
                RuntimeError(message)), expected)
        self.assertEqual(applied.safe_airgap_failure_code(
            RuntimeError("private token in origin header")), "unclassified")

    def test_http_connect_ip_request_and_exact_echo_on_three_mixed_inbounds(self):
        class Conn:
            def __init__(self, response):
                self.received = bytearray(response)
                self.writes = []
                self.closed = False
                self.timeout = None
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True
            def settimeout(self, timeout):
                self.timeout = timeout
            def sendall(self, data):
                self.writes.append(data)
            def recv(self, size):
                amount = min(size, len(self.received))
                chunk = bytes(self.received[:amount])
                del self.received[:amount]
                return chunk

        for port in applied.MANAGED_PORTS:
            with self.subTest(port=port):
                payload = b"http-connect-ip-" + str(port).encode()
                response = (b"HTTP/1.1 200 Connection established\r\n"
                            b"Via: private-test\r\n\r\n" +
                            loopback.REPLY_PREFIX + payload)
                conn = Conn(response)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as opened:
                    applied.probe_http_connect_ip(port, 41001, payload)
                opened.assert_called_once_with(("127.0.0.1", port), timeout=4)
                self.assertTrue(conn.closed)
                self.assertEqual(conn.timeout, 4)
                self.assertEqual(conn.writes[0],
                                 b"CONNECT 127.0.0.1:41001 HTTP/1.1\r\n"
                                 b"Host: 127.0.0.1:41001\r\n\r\n")
                self.assertEqual(conn.writes[1], payload)

        payload = b"local-http"
        for response in (
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",  # Truncated header
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * 1200,
            b"HTTP/1.1 202 Accepted\r\n\r\n",
            b"NOTHTTP 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nwrong",
        ):
            with self.subTest(response=response[:40]):
                conn = Conn(response)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_connect_ip(2082, 41001, payload)
                self.assertTrue(conn.closed)

        for port, echo, message in (
            (True, 41001, payload), (2089, 41001, payload),
            (2082, True, payload), (2082, 0, payload),
            (2082, 65536, payload), (2082, 41001, ""),
            (2082, 41001, b""), (2082, 41001, b"x" * 129),
        ):
            with self.subTest(port=port, echo=echo):
                with mock.patch.object(applied.socket, "create_connection") as opened:
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_connect_ip(port, echo, message)
                    opened.assert_not_called()

    def test_http_connect_selected_only_and_generation_guard(self):
        class Node:
            calls = 8
            rejections = 3
            reject_connections = False
            failed = False
        good = self.promoted_status(pid=222)
        node = Node()
        connections = []
        def dial(port, echo, message):
            self.assertEqual(echo, 41001)
            self.assertEqual(message, b"http-connect-ip-" + str(port).encode())
            connections.append(port)
            if port == 2082:
                node.calls += 1
        with mock.patch.object(applied, "unix_json", return_value=good) as api:
            with mock.patch.object(applied, "probe_http_connect_ip",
                                   side_effect=dial) as probe:
                self.assertEqual(applied.probe_http_route_isolation(
                    "/daemon.sock", 5, 9, 222, 41001, node), 3)
        self.assertEqual(connections, list(applied.MANAGED_PORTS))
        self.assertEqual((node.calls, node.rejections), (9, 3))
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(api.call_count, 2)

        for defect in ("wrong-pid", "rule-uses-selected", "selected-bypasses",
                       "new-rejection", "pid-replaced-after-traffic"):
            with self.subTest(defect=defect):
                node = Node()
                def bad_dial(port, _echo, _message):
                    if defect == "rule-uses-selected" and port == 2080:
                        node.calls += 1
                    if port == 2082 and defect != "selected-bypasses":
                        node.calls += 1
                    if defect == "new-rejection" and port == 2080:
                        node.rejections += 1
                statuses = (
                    [dict(good, core_pid=333)] if defect == "wrong-pid" else
                    [good, dict(good, core_pid=333)] if
                    defect == "pid-replaced-after-traffic" else [good, good]
                )
                with mock.patch.object(applied, "unix_json",
                                       side_effect=statuses):
                    with mock.patch.object(applied, "probe_http_connect_ip",
                                           side_effect=bad_dial) as dial:
                        with self.assertRaises(RuntimeError):
                            applied.probe_http_route_isolation(
                                "/daemon.sock", 5, 9, 222, 41001, node)
                        if defect == "wrong-pid":
                            dial.assert_not_called()



    def test_parallel_http_selected_only_and_exact_distinct_audit_tags(self):
        class Node:
            def __init__(self):
                self.calls = 11
                self.rejections = 4
                self.parallel_payloads = [b"prior-tag"]
                self.failed = False
                self.reject_connections = False

        node = Node()
        received = []
        lock = threading.Lock()
        def fake_connect(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            self.assertIn(port, applied.MANAGED_PORTS)
            self.assertEqual(len(payload), 32)
            with lock:
                received.append((port, payload))
                if port == 2082:
                    node.calls += 1
                    node.parallel_payloads.append(payload)

        with mock.patch.object(applied, "unix_json",
                               return_value=self.promoted_status(pid=222)) as api:
            with mock.patch.object(applied, "probe_http_connect_ip",
                                   side_effect=fake_connect) as dial:
                result = applied.probe_parallel_http_connects(
                    "/sock", 5, 9, 222, 41001, node)
        self.assertEqual(result, 12)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(dial.call_count, 12)
        self.assertEqual((node.calls, node.rejections), (15, 4))
        self.assertEqual([sum(port == k for port, _ in received)
                          for k in applied.MANAGED_PORTS], [4, 4, 4])
        self.assertEqual(len(set(payload for _, payload in received)), 12)
        self.assertEqual(set(node.parallel_payloads[1:]), {
            applied.parallel_probe_payload(i, j, 2082)
            for i in (2, 5) for j in (0, 1)
        })
        self.assertEqual(node.parallel_payloads[0], b"prior-tag")
        self.assertFalse(node.failed)

    def test_parallel_http_rejects_stale_core_bypass_duplicate_and_fd_failure(self):
        class Node:
            def __init__(self):
                self.calls = 11
                self.rejections = 4
                self.parallel_payloads = [b"prior-tag"]
                self.failed = False
                self.reject_connections = False
        params = ("/sock", 5, 9, 222, 41001)
        for invalid in ("bad-pid", "bad-port", "bad-tags", "node-failed",
                        "node-rejecting"):
            with self.subTest(invalid=invalid):
                node = Node()
                pid, port = 222, 41001
                if invalid == "bad-pid":
                    pid = True
                if invalid == "bad-port":
                    port = 65536
                if invalid == "bad-tags":
                    node.parallel_payloads = None
                if invalid == "node-failed":
                    node.failed = True
                if invalid == "node-rejecting":
                    node.reject_connections = True
                with mock.patch.object(applied, "unix_json") as api:
                    with mock.patch.object(applied, "probe_http_connect_ip") as dial:
                        with self.assertRaises(RuntimeError):
                            applied.probe_parallel_http_connects(
                                "/sock", 5, 9, pid, port, node)
                        api.assert_not_called()
                        dial.assert_not_called()

        good = self.promoted_status(pid=222)
        changed = self.promoted_status(pid=333)
        for defect in ("wrong-start", "changed-pid", "selected-bypass",
                       "rule-cross", "compensating-cross", "duplicate-tag",
                       "new-refusal", "upstream-failed", "worker-error"):
            with self.subTest(defect=defect):
                node = Node()
                lock = threading.Lock()
                def corrupt(port, target, payload):
                    self.assertEqual(target, 41001)
                    with lock:
                        if defect == "worker-error" and port == 2081:
                            raise RuntimeError("injected HTTP worker failure")
                        skip_selected = (
                            defect == "compensating-cross" and payload ==
                            applied.parallel_probe_payload(5, 1, 2082)
                        )
                        if port == 2082 and defect != "selected-bypass" and not skip_selected:
                            node.calls += 1
                            tag = (applied.parallel_probe_payload(2, 0, 2082)
                                   if defect == "duplicate-tag" else payload)
                            node.parallel_payloads.append(tag)
                        if port == 2080 and defect == "rule-cross":
                            node.calls += 1
                            node.parallel_payloads.append(payload)
                        if defect == "compensating-cross" and payload == (
                            applied.parallel_probe_payload(0, 0, 2080)
                        ):
                            node.calls += 1
                            node.parallel_payloads.append(payload)
                        if port == 2082 and defect == "new-refusal":
                            node.rejections += 1
                        if port == 2082 and defect == "upstream-failed":
                            node.failed = True
                responses = ([changed] if defect == "wrong-start" else
                             [good, changed] if defect == "changed-pid" else
                             [good, good])
                with mock.patch.object(applied, "unix_json",
                                       side_effect=responses):
                    with mock.patch.object(applied, "probe_http_connect_ip",
                                           side_effect=corrupt) as dial:
                        with self.assertRaises(RuntimeError):
                            applied.probe_parallel_http_connects(
                                *params, node)
                        if defect == "wrong-start":
                            dial.assert_not_called()

        self.assertEqual(applied.safe_airgap_failure_code(RuntimeError(
            "parallel HTTP CONNECT crossed or bypassed Selected node")),
            "http-parallel-route-bypass")
        self.assertEqual(applied.safe_airgap_failure_code(RuntimeError(
            "parallel HTTP CONNECT changed approved Core PID or generation")),
            "http-parallel-core-replaced")


    def test_parallel_http_selected_refusal_keeps_rule_direct_healthy(self):
        class Node:
            def __init__(self):
                self.calls = 15
                self.rejections = 5
                self.parallel_payloads = [b"earlier-selected"]
                self.reject_connections = False
                self.failed = False

        node = Node()
        routed, denied = [], []
        lock = threading.Lock()
        def healthy(port, echo_port, payload):
            self.assertEqual(echo_port, 41001)
            self.assertTrue(node.reject_connections)
            self.assertIn(port, (2080, 2081))
            self.assertTrue(payload.startswith(b"http-parallel-denied-"))
            self.assertTrue(payload.endswith(str(port).encode("ascii")))
            with lock:
                routed.append((port, payload))

        def refuse(echo_port):
            self.assertEqual(echo_port, 41001)
            self.assertTrue(node.reject_connections)
            with lock:
                node.rejections += 1
                denied.append(echo_port)

        with mock.patch.object(applied, "unix_json",
                               return_value=self.promoted_status(pid=222)) as api:
            with mock.patch.object(applied, "probe_http_connect_ip",
                                   side_effect=healthy) as http:
                with mock.patch.object(applied, "probe_http_selected_refusal",
                                       side_effect=refuse) as selected:
                    completed = applied.probe_parallel_http_selected_denials(
                        "/sock", 5, 9, 222, 41001, node)
        self.assertEqual(completed, 12)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(http.call_count, 8)
        self.assertEqual(selected.call_count, 4)
        self.assertEqual([sum(port == p for port, _ in routed)
                          for p in (2080, 2081)], [4, 4])
        self.assertEqual(len(set(payload for _, payload in routed)), 8)
        self.assertEqual(denied, [41001] * 4)
        self.assertEqual((node.calls, node.rejections), (15, 9))
        self.assertEqual(node.parallel_payloads, [b"earlier-selected"])
        self.assertFalse(node.reject_connections)
        self.assertFalse(node.failed)

    def test_parallel_http_selected_refusal_rejects_invalid_fixture_without_io(self):
        class Node:
            def __init__(self):
                self.calls = 15
                self.rejections = 5
                self.parallel_payloads = []
                self.reject_connections = False
                self.failed = False

        for defect in ("bad-pid", "bad-port", "bad-calls", "bad-rejections",
                       "bad-tags", "failed", "already-rejecting"):
            with self.subTest(defect=defect):
                node = Node()
                pid, port = 222, 41001
                if defect == "bad-pid":
                    pid = True
                if defect == "bad-port":
                    port = 0
                if defect == "bad-calls":
                    node.calls = True
                if defect == "bad-rejections":
                    node.rejections = -1
                if defect == "bad-tags":
                    node.parallel_payloads = None
                if defect == "failed":
                    node.failed = True
                if defect == "already-rejecting":
                    node.reject_connections = True
                with mock.patch.object(applied, "unix_json") as api:
                    with mock.patch.object(applied, "probe_http_connect_ip") as http:
                        with self.assertRaises(RuntimeError):
                            applied.probe_parallel_http_selected_denials(
                                "/sock", 5, 9, pid, port, node)
                        api.assert_not_called()
                        http.assert_not_called()

    def test_parallel_http_selected_refusal_is_fail_closed_even_with_bad_counts(self):
        class Node:
            def __init__(self):
                self.calls = 15
                self.rejections = 5
                self.parallel_payloads = [b"earlier-selected"]
                self.reject_connections = False
                self.failed = False

        good = self.promoted_status(pid=222)
        drift = self.promoted_status(pid=333)
        for defect in ("stale-start", "changed-pid", "rule-cross",
                       "selected-bypass", "rejection-storm", "tag-cross",
                       "upstream-failed", "worker-failed"):
            with self.subTest(defect=defect):
                node = Node()
                lock = threading.Lock()
                def healthy(port, _echo, _payload):
                    with lock:
                        if defect == "worker-failed" and port == 2080:
                            raise RuntimeError("synthetic HTTP worker error")
                        if defect == "rule-cross" and port == 2080:
                            node.calls += 1
                        if defect == "tag-cross" and port == 2081:
                            node.parallel_payloads.append(b"invalid-selected")
                def refused(_echo):
                    with lock:
                        if defect != "selected-bypass":
                            node.rejections += (
                                5 if defect == "rejection-storm" else 1)
                        if defect == "upstream-failed":
                            node.failed = True
                statuses = ([drift] if defect == "stale-start" else
                            [good, drift] if defect == "changed-pid" else
                            [good, good])
                with mock.patch.object(applied, "unix_json",
                                       side_effect=statuses):
                    with mock.patch.object(applied, "probe_http_connect_ip",
                                           side_effect=healthy) as http:
                        with mock.patch.object(applied, "probe_http_selected_refusal",
                                               side_effect=refused):
                            with self.assertRaises(RuntimeError):
                                applied.probe_parallel_http_selected_denials(
                                    "/sock", 5, 9, 222, 41001, node)
                        if defect == "stale-start":
                            http.assert_not_called()
                self.assertFalse(node.reject_connections)

        self.assertEqual(applied.safe_airgap_failure_code(RuntimeError(
            "parallel HTTP Selected refusal bypassed or harmed Rule/Direct")),
            "http-parallel-refusal-bypass")
        self.assertEqual(applied.safe_airgap_failure_code(RuntimeError(
            "parallel HTTP Selected refusal unexpectedly restarted Core")),
            "http-parallel-refusal-core-changed")
        self.assertEqual(applied.safe_airgap_failure_code(RuntimeError(
            "private Selected URL and credentials")), "unclassified")

    def test_http_selected_refusal_accepts_only_complete_error_or_empty_close(self):
        class Conn:
            def __init__(self, data=b"", error=None):
                self.chunks = bytearray(data)
                self.error = error
                self.writes = []
                self.closed = False
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                self.closed = True
            def settimeout(self, n):
                self.timeout = n
            def sendall(self, data):
                self.writes.append(data)
            def recv(self, n):
                if self.chunks:
                    result = bytes(self.chunks[:n])
                    del self.chunks[:n]
                    return result
                if self.error is not None:
                    raise self.error
                return b""

        valid = [
            (b"", None), (b"", ConnectionResetError("reset")),
            (b"", ConnectionAbortedError("abort")),
            (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", None),
            (b"HTTP/1.0 403 Forbidden\r\n\r\n", None),
            # A premature 200 is only accepted after an application probe
            # sees no payload bytes and the tunnel immediately closes.
            (b"HTTP/1.1 200 Connection established\r\n\r\n", None),
            (b"HTTP/1.1 200 Connection established\r\n\r\n",
             ConnectionResetError("upstream-refused")),
        ]
        request = (b"CONNECT 127.0.0.1:41001 HTTP/1.1\r\n"
                   b"Host: 127.0.0.1:41001\r\n\r\n")
        for response, error in valid:
            with self.subTest(valid=response[:15], error=type(error).__name__):
                conn = Conn(response, error)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn) as dial:
                    applied.probe_http_selected_refusal(41001)
                dial.assert_called_once_with(("127.0.0.1", 2082), timeout=4)
                if b" 200 " in response:
                    self.assertEqual(conn.writes,
                                     [request, b"http-selected-must-not-echo"])
                else:
                    self.assertEqual(conn.writes, [request])
                self.assertEqual(conn.timeout, 4)
                self.assertTrue(conn.closed)
        invalid = [
            (b"HTTP/1.1 200 Connection established\r\n\r\n" +
             loopback.REPLY_PREFIX + b"http-selected-must-not-echo", None),
            (b"HTTP/1.1 200 Connection established\r\n\r\n",
             socket.timeout("leaked-stall")),
            (b"HTTP/1.1 204 No Content\r\n\r\n", None),
            (b"HTTP/1.1 302 Found\r\n\r\n", None),
            (b"HTTP/1.1 502 Bad Gateway\r\n", None),
            (b"HTTP/1.1 502 Bad Gateway\r\n", ConnectionResetError()),
            (b"HTTP/1.1 502\r\nX: " + b"x" * 1100, None),
            (b"BROKEN 502 Bad Gateway\r\n\r\n", None),
        ]
        for response, error in invalid:
            with self.subTest(invalid=response[:25]):
                conn = Conn(response, error)
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=conn):
                    with self.assertRaises(RuntimeError):
                        applied.probe_http_selected_refusal(41001)
                self.assertTrue(conn.closed)
        for echo in (0, -1, 65536, True, "41001", 41001.5):
            with mock.patch.object(applied.socket, "create_connection") as dial:
                with self.assertRaises(RuntimeError):
                    applied.probe_http_selected_refusal(echo)
                dial.assert_not_called()
        with mock.patch.object(applied.socket, "create_connection",
                               return_value=Conn(error=socket.timeout("hang"))):
            with self.assertRaises(socket.timeout):
                applied.probe_http_selected_refusal(41001)

    def test_http_selected_upstream_failure_isolates_rule_and_recovers(self):
        class Node:
            calls = 8
            rejections = 3
            failed = False
            reject_connections = False

        node = Node()
        ports = []
        def route(port, target, payload):
            self.assertTrue(node.reject_connections)
            self.assertEqual(target, 41001)
            self.assertEqual(payload, b"http-denied-" + str(port).encode())
            ports.append(port)
        def selected(_target):
            self.assertTrue(node.reject_connections)
            node.rejections += 1
        def recovery(*_args):
            self.assertFalse(node.reject_connections)
            node.calls += 1
            return 3
        with mock.patch.object(applied, "unix_json",
                               return_value=self.promoted_status(pid=222)) as api:
            with mock.patch.object(applied, "probe_http_connect_ip",
                                   side_effect=route) as proxy:
                with mock.patch.object(applied, "probe_http_selected_refusal",
                                       side_effect=selected) as denied:
                    with mock.patch.object(applied, "probe_http_route_isolation",
                                           side_effect=recovery) as recovered:
                        stages = []
                        result = applied.probe_http_selected_failure_isolation(
                            "/daemon.sock", 5, 9, 222, 41001, node,
                            stage_hook=stages.append)
        self.assertEqual(stages, [
            "http-failure-preflight", "http-failure-rule",
            "http-failure-direct", "http-failure-selected-response",
            "http-failure-node-audit", "http-failure-pid-after-restore",
            "http-failure-three-inbound-recovery",
            "http-failure-final-audit",
        ])
        self.assertEqual(result, 3)
        self.assertEqual(ports, [2080, 2081])
        self.assertEqual((node.calls, node.rejections), (9, 4))
        self.assertFalse(node.reject_connections)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(proxy.call_count, 2)
        denied.assert_called_once_with(41001)
        recovered.assert_called_once()

    def test_http_failure_diagnostics_fail_before_any_core_contact(self):
        with mock.patch.object(applied, "unix_json") as api:
            with mock.patch.object(applied, "probe_http_connect_ip") as dial:
                with self.assertRaises(RuntimeError):
                    applied.probe_http_selected_failure_isolation(
                        "/sock", 5, 9, 222, 41001, object(),
                        stage_hook="not-callable")
                with self.assertRaises(RuntimeError):
                    applied.probe_restart_after_held_stop(
                        "/app", {}, "/sock", 100, "/core", 5, 9,
                        41001, object(), "b" * 64, stage_hook="unsafe")
                api.assert_not_called()
                dial.assert_not_called()
        for reason, expected in (
            ("HTTP Selected failure bypassed or did not reach upstream",
             "http-selected-refusal-not-observed"),
            ("HTTP Selected sent success or malformed refusal",
             "http-selected-unsafe-response"),
            ("HTTP Selected recovery bypassed or changed route audit",
             "http-selected-recovery-bypass"),
            ("HTTP Selected premature 200 tunnel forwarded data",
             "http-selected-200-forwarded"),
            ("HTTP Selected premature 200 tunnel did not close",
             "http-selected-200-stalled"),
        ):
            self.assertEqual(
                applied.safe_airgap_failure_code(RuntimeError(reason)),
                expected)
        self.assertEqual(
            applied.safe_airgap_failure_code(
                RuntimeError("HTTP secret path and token")),
            "unclassified")

    def test_http_selected_failure_rejects_pid_drift_and_any_bypass(self):
        class Node:
            def __init__(self):
                self.calls = 8
                self.rejections = 3
                self.failed = False
                self.reject_connections = False
        good = self.promoted_status(pid=222)
        stale = self.promoted_status(pid=333)
        for defect in ("stale", "rule-cross", "not-rejected",
                       "selected-success", "pid-replaced", "recovery-bypass"):
            with self.subTest(defect=defect):
                node = Node()
                def proxy(port, _echo, _data):
                    if defect == "rule-cross" and port == 2080:
                        node.calls += 1
                def refusal(_echo):
                    if defect == "selected-success":
                        raise RuntimeError("unexpected HTTP 200")
                    if defect != "not-rejected":
                        node.rejections += 1
                def recover(*_args):
                    if defect != "recovery-bypass":
                        node.calls += 1
                    return 3
                statuses = ([stale] if defect == "stale" else
                            [good, stale] if defect == "pid-replaced" else
                            [good, good])
                with mock.patch.object(applied, "unix_json",
                                       side_effect=statuses):
                    with mock.patch.object(applied, "probe_http_connect_ip",
                                           side_effect=proxy) as called:
                        with mock.patch.object(applied, "probe_http_selected_refusal",
                                               side_effect=refusal):
                            with mock.patch.object(applied, "probe_http_route_isolation",
                                                   side_effect=recover) as recovery:
                                with self.assertRaises(RuntimeError):
                                    applied.probe_http_selected_failure_isolation(
                                        "/daemon.sock", 5, 9, 222, 41001, node)
                self.assertFalse(node.reject_connections)
                if defect == "stale":
                    called.assert_not_called()
                if defect != "recovery-bypass":
                    recovery.assert_not_called()

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


    def test_synthetic_socks_domain_maps_only_reserved_name_to_local_echo(self):
        with (loopback.LoopbackServer(
                  ("127.0.0.1", 0), loopback.LoopbackResponder) as echo,
              applied.LocalSocksServer(
                  ("127.0.0.1", 0), applied.LocalSocksNode) as node):
            node.echo_port = echo.server_address[1]
            echo_thread = threading.Thread(
                target=echo.serve_forever, daemon=True)
            node_thread = threading.Thread(
                target=node.serve_forever, daemon=True)
            echo_thread.start()
            node_thread.start()
            try:
                payload = b"domain-relay-success"
                domain = applied.SOCKS_DOMAIN_TARGET
                with socket.create_connection(node.server_address,
                                              timeout=3) as conn:
                    conn.settimeout(3)
                    conn.sendall(b"\x05\x01\x00")
                    self.assertEqual(applied.exact_read(conn, 2), b"\x05\x00")
                    conn.sendall(
                        b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain +
                        struct.pack("!H", node.echo_port))
                    self.assertEqual(applied.exact_read(conn, 4),
                                     b"\x05\x00\x00\x01")
                    self.assertEqual(applied.exact_read(conn, 4),
                                     b"\x7f\x00\x00\x01")
                    self.assertEqual(
                        struct.unpack("!H", applied.exact_read(conn, 2))[0],
                        node.echo_port)
                    conn.sendall(payload)
                    self.assertEqual(
                        applied.exact_read(conn,
                                           len(loopback.REPLY_PREFIX) +
                                           len(payload)),
                        loopback.REPLY_PREFIX + payload)
                self.assertEqual(node.calls, 1)
                self.assertEqual(node.rejections, 0)
                self.assertEqual(node.hostname_requests,
                                 [(domain, node.echo_port)])
                self.assertFalse(node.failed)
            finally:
                node.shutdown()
                echo.shutdown()
                node_thread.join(timeout=4)
                echo_thread.join(timeout=4)

    def test_synthetic_socks_domain_blocks_unapproved_name_or_port_no_dial(self):
        for name, use_port in (
            (b"x" + applied.SOCKS_DOMAIN_TARGET[1:], 41001),
            (applied.SOCKS_DOMAIN_TARGET, 41002),
            (b"unexpected-longer.invalid", 41001),
        ):
            with self.subTest(name=name, port=use_port):
                with applied.LocalSocksServer(
                        ("127.0.0.1", 0),
                        applied.LocalSocksNode) as node:
                    node.echo_port = 41001
                    thread = threading.Thread(
                        target=node.serve_forever, daemon=True)
                    thread.start()
                    try:
                        # No target dial is possible, including a guessed
                        # host lookup or an external network connection.
                        with mock.patch.object(
                                applied.socket, "create_connection",
                                side_effect=AssertionError(
                                    "unapproved synthetic outbound")) as dial:
                            with socket.socket(
                                    socket.AF_INET, socket.SOCK_STREAM) as conn:
                                conn.settimeout(3)
                                conn.connect(node.server_address)
                                conn.sendall(b"\x05\x01\x00")
                                self.assertEqual(
                                    applied.exact_read(conn, 2), b"\x05\x00")
                                conn.sendall(
                                    b"\x05\x01\x00\x03" +
                                    bytes([len(name)]) + name +
                                    struct.pack("!H", use_port))
                                try:
                                    self.assertEqual(conn.recv(1), b"")
                                except (ConnectionResetError,
                                        ConnectionAbortedError):
                                    pass
                            for _ in range(100):
                                if node.failed:
                                    break
                                threading.Event().wait(0.01)
                            self.assertTrue(node.failed)
                            dial.assert_not_called()
                        self.assertEqual(node.calls, 0)
                        self.assertEqual(node.rejections, 0)
                        self.assertEqual(node.hostname_requests, [])
                    finally:
                        node.shutdown()
                        thread.join(timeout=4)

    def test_synthetic_relay_distinguishes_post_echo_reset_from_early_failure(self):
        # No Core, Docker, external network, or arbitrary retry required.
        # The real local handler is exercised with deterministic socket I/O.
        for exception in (ConnectionResetError("reset"),
                          ConnectionAbortedError("aborted"),
                          BrokenPipeError("pipe")):
            self.assertTrue(applied.is_post_echo_peer_reset(exception, True))
            self.assertFalse(applied.is_post_echo_peer_reset(exception, False))
        for exception in (OSError("unexpected I/O"), RuntimeError("bad CONNECT"),
                          socket.timeout("timeout")):
            self.assertFalse(applied.is_post_echo_peer_reset(exception, True))
        self.assertFalse(applied.is_post_echo_peer_reset(
            ConnectionResetError("reset"), 1))

        def run_handler(disconnect, after_reply):
            incoming = mock.Mock()
            incoming.recv.side_effect = (
                [b"local-test-payload", disconnect] if after_reply
                else [disconnect]
            )
            target = mock.MagicMock()
            target.__enter__.return_value = target
            target.recv.return_value = loopback.REPLY_PREFIX + b"local-test-payload"
            server = mock.Mock(echo_port=41001, reject_connections=False,
                               calls=0, failed=False,
                               counter_lock=threading.Lock(),
                               parallel_payloads=[])
            reads = [b"\x05\x01", b"\x00",
                     b"\x05\x01\x00\x01",
                     b"\x7f\x00\x00\x01",
                     struct.pack("!H", 41001)]
            ready = ([([incoming], [], []), ([target], [], []),
                      ([incoming], [], [])] if after_reply
                     else [([incoming], [], [])])
            with mock.patch.object(applied, "exact_read", side_effect=reads):
                with mock.patch.object(applied.socket, "create_connection",
                                       return_value=target):
                    with mock.patch.object(applied.select, "select",
                                           side_effect=ready):
                        applied.LocalSocksNode(
                            incoming, ("127.0.0.1", 12345), server)
            self.assertEqual(server.calls, 1)
            if after_reply:
                self.assertIn(
                    loopback.REPLY_PREFIX + b"local-test-payload",
                    [call.args[0] for call in incoming.sendall.call_args_list])
            return server.failed

        for disconnect in (ConnectionResetError("reset"),
                           ConnectionAbortedError("aborted"),
                           BrokenPipeError("pipe")):
            with self.subTest(disconnect=type(disconnect).__name__):
                self.assertFalse(run_handler(disconnect, True))
                self.assertTrue(run_handler(disconnect, False))
        self.assertTrue(run_handler(OSError("other failure"), True))
        self.assertTrue(run_handler(socket.timeout("timeout"), True))

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
