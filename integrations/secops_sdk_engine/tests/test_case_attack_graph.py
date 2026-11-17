import json
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock

from actions.build_kill_chain_timeline import _enforce_timeline_ceiling
from actions.map_entity_blast_radius import _enforce_blast_radius_ceiling
from engine.workflows.case_attack_graph import (
    BuildKillChainTimelineWorkflow,
    CaseAttackTelemetryCollector,
    MapEntityBlastRadiusWorkflow,
    _find_adk_insight_for_identifier,
    build_entity_udm_query,
    extract_adk_overlay,
    read_soar_case_context_json,
    resolve_mitre_metadata,
    write_soar_case_context_json,
)


def _make_sample_investigation():
    return SimpleNamespace(
        case_id="109124",
        display_name="Exchange Webshell & LSASS Credential Dump",
        title="Exchange Webshell & LSASS Credential Dump",
        status="OPEN",
        priority="CRITICAL",
        stage="Investigation",
        created_time="2026-11-16T14:15:00Z",
        alerts=[
            SimpleNamespace(
                identifier="ALERT_LSASS_1",
                name="cases/109124/caseAlerts/1",
                rule_name="LSASS Memory Dump via Rundll32 Comsvcs",
                priority="CRITICAL",
                event_count=1,
                created_time="2026-11-16T14:14:22Z",
                vendor="Google Chronicle",
                raw={"ticketId": "de_alert_lsass", "creationTime": "2026-11-16T14:14:22Z"},
            )
        ],
        entities=[
            SimpleNamespace(
                identifier="EXCH-PROD-02.corp.local",
                entity_type="HOSTNAME",
                role="SRC",
                is_suspicious=False,
                is_pivot=True,
                is_internal=True,
                raw={"isPivot": True, "isInternal": True},
            ),
            SimpleNamespace(
                identifier="svc_backup@corp.local",
                entity_type="USERUNIQNAME",
                role="SRC",
                is_suspicious=True,
                is_pivot=False,
                is_internal=True,
                raw={"isSuspicious": True},
            ),
            SimpleNamespace(
                identifier="185.220.101.42",
                entity_type="ADDRESS",
                role="DST",
                is_suspicious=True,
                is_pivot=False,
                is_internal=False,
                raw={"isSuspicious": True},
            ),
        ],
        comments=[],
        raw={"tags": [{"displayName": "Tier1:Triaged"}, {"displayName": "Verdict:TP"}]},
    )


def _make_cached_correlation():
    return {
        "case_id": "109124",
        "correlate_udm_events": True,
        "lookback_hours": 48,
        "query_used": 'principal.hostname = "EXCH-PROD-02"',
        "entities_searched": [
            {"identifier": "EXCH-PROD-02.corp.local", "type": "HOSTNAME", "role": "SRC"},
            {"identifier": "svc_backup@corp.local", "type": "USER", "role": "SRC"},
            {"identifier": "185.220.101.42", "type": "IP", "role": "DST"},
        ],
        "detections_found": [
            {
                "rule_name": "Webshell Process Spawned by IIS w3wp.exe",
                "rule_id": "ru_webshell_001",
                "alert_state": "NOT_ALERTING",
                "is_alerting": False,
                "severity": "HIGH",
                "event_id": "ev_silent_1",
                "event_type": "PROCESS_LAUNCH",
                "timestamp": "2026-11-16T14:10:05Z",
                "summary": "IIS worker w3wp.exe spawned cmd.exe and certutil",
                "principal": {
                    "hostname": "EXCH-PROD-02.corp.local",
                    "user": {"userid": "IIS APPPOOL\\MSExchangeOWAAppPool"},
                    "process": {"fullPath": "C:\\Windows\\System32\\inetsrv\\w3wp.exe"},
                },
                "target": {
                    "process": {"commandLine": "certutil.exe -urlcache -split -f -decode stage2.b64"},
                },
            },
            {
                "rule_name": "LSASS Memory Dump via Rundll32 Comsvcs",
                "rule_id": "ru_lsass_002",
                "alert_state": "ALERTING",
                "is_alerting": True,
                "severity": "CRITICAL",
                "event_id": "ev_alert_2",
                "event_type": "PROCESS_LAUNCH",
                "timestamp": "2026-11-16T14:14:22Z",
                "summary": "rundll32.exe comsvcs.dll, MiniDump lsass.dmp full",
                "principal": {
                    "hostname": "EXCH-PROD-02.corp.local",
                    "user": {"userid": "svc_backup@corp.local"},
                    "process": {"fullPath": "C:\\Windows\\System32\\rundll32.exe"},
                },
                "target": {
                    "process": {"fullPath": "C:\\Windows\\Temp\\lsass.dmp"},
                },
            },
        ],
        "events_found": [
            {
                "event_id": "ev_udm_1",
                "event_type": "NETWORK_HTTP",
                "timestamp": "2026-11-16T14:08:11Z",
                "description": "Inbound POST /owa/auth/Current/themes/resources/healthcheck.aspx from 185.220.101.42",
                "principal": {"ip": ["185.220.101.42"]},
                "target": {"hostname": "EXCH-PROD-02.corp.local"},
            },
            {
                "event_id": "ev_udm_2",
                "event_type": "PROCESS_LAUNCH",
                "timestamp": "2026-11-16T14:11:30Z",
                "description": "whoami /all && nltest /dclist:corp.local",
                "principal": {
                    "hostname": "EXCH-PROD-02.corp.local",
                    "user": {"userid": "svc_backup@corp.local"},
                },
                "target": {"process": {"commandLine": "nltest /dclist:corp.local"}},
            },
        ],
    }


def _make_adk_tp_result():
    return {
        "response": (
            "# Tier 1 Autonomous Triage Report\n"
            "**Verdict:** True Positive | **Disposition:** Malicious Credential Dumping | **Confidence:** High (96%)\n\n"
            "## Executive Summary\n"
            "Confirmed active compromise on `EXCH-PROD-02.corp.local` originating from Tor exit IP `185.220.101.42`. "
            "Attacker dropped an OWA webshell, pivoted to `svc_backup@corp.local`, and dumped LSASS memory via comsvcs.dll (T1003.001).\n"
            "- `185.220.101.42`: External C2 / Tor exit node delivering webshell POST payloads.\n"
            "- `EXCH-PROD-02.corp.local`: Compromised Exchange server executing w3wp.exe child shells.\n"
            "- `svc_backup@corp.local`: Domain backup service account hijacked for LSASS MiniDump.\n"
        ),
        "execution_time_seconds": 19.4,
        "timestamp": "2026-11-16T14:16:10Z",
    }


class TestCaseAttackGraphWorkflows(unittest.TestCase):
    def test_resolve_mitre_metadata_explicit_and_heuristic(self):
        # Explicit MITRE ID resolution via MitreCatalog
        explicit = resolve_mitre_metadata("Detected credential access technique T1003.001 on host")
        self.assertEqual(explicit["technique_id"], "T1003.001")
        self.assertTrue(len(explicit["technique_name"]) > 0)
        self.assertIn("credential-access", explicit["tactic_slug"])

        # Heuristic resolution when rule/command text has no explicit T-code
        heur = resolve_mitre_metadata("certutil.exe -urlcache -split -f -decode payload.b64")
        self.assertEqual(heur["technique_id"], "T1140")
        self.assertEqual(heur["tactic_slug"], "defense-evasion")

        # Verify MitreCatalog loads from a flattened SOAR Managers/ directory layout
        import tempfile
        from pathlib import Path
        from engine.mitre_catalog import MitreCatalog

        with tempfile.TemporaryDirectory() as tmpd:
            flat_dir = Path(tmpd)
            (flat_dir / "enterprise_matrix.json").write_text(
                json.dumps(
                    {
                        "version": "18.1",
                        "techniques": {"T1003.001": {"id": "T1003.001", "name": "LSASS Memory", "tactics": ["credential-access"]}},
                        "tactics": {"credential-access": {"id": "TA0006", "name": "Credential Access"}},
                    }
                ),
                encoding="utf-8",
            )
            flat_cat = MitreCatalog(data_dir=flat_dir)
            self.assertEqual(flat_cat.get_technique("T1003.001")["name"], "LSASS Memory")

    def test_build_entity_udm_query_templates(self):
        ip_q = build_entity_udm_query("185.220.101.42", "IP")
        self.assertIn('principal.ip = "185.220.101.42"', ip_q)
        self.assertIn('target.ip = "185.220.101.42"', ip_q)

        host_q = build_entity_udm_query("EXCH-PROD-02.corp.local", "HOST")
        self.assertIn("EXCH-PROD-02.corp.local", host_q)
        self.assertIn("EXCH-PROD-02", host_q)

        hash_q = build_entity_udm_query("a" * 64, "FILEHASH")
        self.assertIn("target.file.sha256", hash_q)

    def test_extract_adk_overlay_tp_and_btp(self):
        tp_overlay = extract_adk_overlay(_make_adk_tp_result(), [])
        self.assertTrue(tp_overlay["has_adk_analysis"])
        self.assertEqual(tp_overlay["verdict_tone"], "malicious")
        self.assertIn("True Positive", tp_overlay["verdict"])
        self.assertTrue(len(tp_overlay["summary"]) > 20)
        insight = _find_adk_insight_for_identifier("185.220.101.42", tp_overlay)
        self.assertIn("185.220.101.42", insight)

        btp_overlay = extract_adk_overlay(
            {
                "response": (
                    "**Verdict:** Benign Positive | **Disposition:** Authorized Red Team Simulation | **Confidence:** High\n"
                    "## Summary\nAuthorized purple-team validation exercise."
                )
            },
            [],
        )
        self.assertTrue(btp_overlay["has_adk_analysis"])
        self.assertEqual(btp_overlay["verdict_tone"], "btp")

    def test_map_entity_blast_radius_workflow_tp_and_btp(self):
        adapter = MagicMock()
        inv = _make_sample_investigation()
        corr = _make_cached_correlation()
        related_cache = {
            "related_cases": [
                {
                    "case_id": "109088",
                    "title": "Tor Exit Node Scan Activity",
                    "priority": "HIGH",
                    "is_closed": False,
                    "is_incident": True,
                    "shared_entities": [{"identifier": "185.220.101.42", "type": "IP"}],
                }
            ]
        }

        wf = MapEntityBlastRadiusWorkflow(adapter=adapter)
        wf.collector.investigate_workflow.execute = MagicMock(return_value=inv)

        res = wf.execute(
            case_id="109124",
            lookback_hours=48,
            include_udm_precursors=True,
            include_related_cases=True,
            max_nodes=28,
            adk_result=_make_adk_tp_result(),
            cached_correlation=corr,
            cached_related_cases=related_cache,
            post_wall_comment=True,
        )

        self.assertEqual(res.case_id, "109124")
        self.assertGreaterEqual(len(res.nodes), 6)
        self.assertGreaterEqual(len(res.edges), 5)
        self.assertTrue(res.adk_overlay["has_adk_analysis"])
        self.assertEqual(res.adk_overlay["verdict_tone"], "malicious")
        self.assertGreaterEqual(res.metrics["silent_rules_count"], 1)
        self.assertGreaterEqual(res.metrics["alerting_rules_count"], 1)
        self.assertEqual(res.metrics["related_case_nodes_count"], 1)
        adapter.create_case_comment.assert_called_once()

        # Verify no orphan seeded case entities exist and coordinates are assigned
        connected = set()
        for ed in res.edges:
            connected.add(ed["from"])
            connected.add(ed["to"])
        for node in res.nodes:
            self.assertIn("x", node)
            self.assertIn("y", node)
            if node["identifier"] in ("EXCH-PROD-02.corp.local", "svc_backup@corp.local", "185.220.101.42"):
                self.assertIn(node["id"], connected)

        # Verify Benign Positive (BTP) risk de-escalation
        inv_btp = _make_sample_investigation()
        for e in inv_btp.entities:
            e.is_suspicious = False
        wf.collector.investigate_workflow.execute = MagicMock(return_value=inv_btp)
        res_btp = wf.execute(
            case_id="109124",
            adk_result={"response": "**Verdict:** Benign Positive | **Disposition:** Authorized Admin Activity"},
            cached_correlation=corr,
            cached_related_cases=related_cache,
        )
        self.assertEqual(res_btp.adk_overlay["verdict_tone"], "btp")
        silent_rule_nodes = [n for n in res_btp.nodes if n["node_type"] == "RULE" and not n["is_alerting"]]
        self.assertTrue(all(n["risk"] == "benign" for n in silent_rule_nodes))

    def test_build_kill_chain_timeline_workflow_lanes_and_stages(self):
        adapter = MagicMock()
        inv = _make_sample_investigation()
        corr = _make_cached_correlation()

        wf = BuildKillChainTimelineWorkflow(adapter=adapter)
        wf.collector.investigate_workflow.execute = MagicMock(return_value=inv)

        res = wf.execute(
            case_id="109124",
            lookback_hours=48,
            include_udm_precursors=True,
            max_timeline_events=30,
            adk_result=_make_adk_tp_result(),
            cached_correlation=corr,
            post_wall_comment=False,
        )

        self.assertEqual(res.case_id, "109124")
        lanes_present = {ev["lane"] for ev in res.events}
        self.assertIn("UDM", lanes_present)
        self.assertIn("SILENT", lanes_present)
        self.assertIn("ALERT", lanes_present)
        self.assertIn("SOAR_ADK", lanes_present)

        # Verify chronological ascending sort on epoch_ms
        epochs = [ev["epoch_ms"] for ev in res.events if ev.get("epoch_ms")]
        self.assertEqual(epochs, sorted(epochs))

        # Verify MITRE ATT&CK stage ribbons populated & 100% milestone stage accounting
        active_stages = [st for st in res.mitre_stages if st.get("count", 0) > 0]
        tactic_slugs = [st["slug"] for st in active_stages]
        self.assertIn("credential-access", tactic_slugs)
        self.assertGreaterEqual(len(active_stages), 2)
        self.assertTrue(all(ev.get("stage_slug") for ev in res.events))
        self.assertTrue(all(ev.get("primary_entity_key") for ev in res.events))
        self.assertGreaterEqual(len(res.entity_lanes), 2)

        # Verify SOAR Case Alert milestones inherit involved case entities
        alert_milestones = [ev for ev in res.events if ev["lane"] == "ALERT" and ev["title"].startswith("SOAR Alert:")]
        self.assertEqual(len(alert_milestones), 1)
        self.assertGreaterEqual(len(alert_milestones[0]["entities"]), 1)

    def test_kill_chain_mitre_precedence_and_identity_canonicalization(self):
        # "Entra ID" must NOT false-positive on Unix `id` (T1033), and Password Spray must map to T1110.003
        spray = resolve_mitre_metadata("Azure Entra ID Password Spray")
        self.assertEqual(spray["technique_id"], "T1110.003")
        self.assertEqual(spray["tactic_slug"], "credential-access")

        tor_login = resolve_mitre_metadata("Azure Successful Service Login from Tor")
        self.assertEqual(tor_login["technique_id"], "T1078")
        self.assertEqual(tor_login["tactic_slug"], "initial-access")

        # AD discovery wrapped in cmd.exe must resolve to Discovery (T1087 / T1482), not generic Execution (T1059)
        ad_disc = resolve_mitre_metadata(
            "Net Group Domain Admin Interaction",
            "",
            'corp-ws-cjohnson.corp.contoso.local "cmd.exe" net group "Domain Admins" /domain',
        )
        self.assertEqual(ad_disc["tactic_slug"], "discovery")
        self.assertEqual(ad_disc["technique_id"], "T1087")

        dc_enum = resolve_mitre_metadata("Nltest Domain Controller Enumeration", "", '"cmd.exe" nltest /dclist:corp.local')
        self.assertEqual(dc_enum["tactic_slug"], "discovery")
        self.assertEqual(dc_enum["technique_id"], "T1482")

        # Verify cloud UPN (cjohnson@corp.contoso.com) and AD short user (cjohnson) merge onto USER:cjohnson lane
        adapter = MagicMock()
        inv = _make_sample_investigation()
        corr = {
            "case_id": "109124",
            "correlate_udm_events": True,
            "lookback_hours": 48,
            "detections_found": [
                {
                    "rule_name": "Azure Entra ID Password Spray",
                    "rule_id": "ru_1",
                    "is_alerting": False,
                    "severity": "MEDIUM",
                    "event_id": "e1",
                    "event_type": "USER_LOGIN",
                    "timestamp": "2026-11-16T17:31:49Z",
                    "principal": {"ip": ["185.220.101.45"]},
                    "target": {"user": {"userid": "cjohnson@corp.contoso.com", "userDisplayName": "Johnson, Craig"}},
                },
                {
                    "rule_name": "Net Group Domain Admin Interaction",
                    "rule_id": "ru_2",
                    "is_alerting": False,
                    "severity": "MEDIUM",
                    "event_id": "e2",
                    "event_type": "PROCESS_LAUNCH",
                    "timestamp": "2026-11-16T17:37:01Z",
                    "principal": {"hostname": "corp-ws-cjohnson.corp.contoso.local", "user": {"userid": "cjohnson"}},
                    "target": {"process": {"commandLine": 'net group "Domain Admins" /domain'}},
                },
            ],
            "events_found": [],
        }
        wf = BuildKillChainTimelineWorkflow(adapter=adapter)
        wf.collector.investigate_workflow.execute = MagicMock(return_value=inv)
        res = wf.execute(case_id="109124", cached_correlation=corr)
        cj_events = [e for e in res.events if e["primary_entity_key"] == "USER:cjohnson"]
        self.assertEqual(len(cj_events), 2)

    def test_collector_upgrades_correlation_when_udm_events_missing_from_cache(self):
        adapter = MagicMock()
        inv = _make_sample_investigation()
        collector = CaseAttackTelemetryCollector(adapter=adapter)
        collector.investigate_workflow.execute = MagicMock(return_value=inv)

        # Simulate prior Correlate Silent Detections cache where correlate_udm_events was False
        partial_cache = {
            "case_id": "109124",
            "correlate_udm_events": False,
            "detections_found": [],
            "events_found": [],
        }
        upgraded_res = {
            "case_id": "109124",
            "correlate_udm_events": True,
            "query_used": 'principal.hostname = "EXCH-PROD-02"',
            "entities_searched": [],
            "detections_found": [],
            "events_found": [{"event_id": "ev_new_udm", "event_type": "PROCESS_LAUNCH", "timestamp": "2026-11-16T14:09:00Z"}],
        }
        collector.correlate_workflow.execute = MagicMock(return_value=upgraded_res)

        bundle = collector.collect(
            case_id="109124",
            include_udm_precursors=True,
            include_related_cases=False,
            cached_correlation=partial_cache,
        )
        collector.correlate_workflow.execute.assert_called_once()
        self.assertEqual(len(bundle["corr_dict"]["events_found"]), 1)

    def test_case_context_helpers_and_payload_ceilings(self):
        store = {}
        mock_siemplify = SimpleNamespace(
            get_case_context_property=lambda key: store.get(key),
            set_case_context_property=lambda key, val: store.__setitem__(key, val),
        )

        ok = write_soar_case_context_json(mock_siemplify, "109124", "TEST_KEY", {"hello": "world"})
        self.assertTrue(ok)
        loaded = read_soar_case_context_json(mock_siemplify, "109124", "TEST_KEY")
        self.assertEqual(loaded, {"hello": "world"})

        # Blast radius payload ceiling
        huge_graph = {
            "nodes": [{"id": f"n_{i}", "blob": "X" * 4000} for i in range(40)],
            "edges": [{"from": f"n_{i}", "to": f"n_{i+1}"} for i in range(39)],
        }
        trimmed_graph = _enforce_blast_radius_ceiling(huge_graph, max_bytes=35_000)
        self.assertLessEqual(len(json.dumps(trimmed_graph).encode("utf-8")), 35_000)
        valid_ids = {n["id"] for n in trimmed_graph["nodes"]}
        self.assertTrue(all(e["from"] in valid_ids and e["to"] in valid_ids for e in trimmed_graph["edges"]))

        # Kill-chain timeline payload ceiling (trims UDM events first, preserves ALERT/SILENT)
        huge_tl = {
            "events": [
                {"id": "alert_1", "lane": "ALERT", "blob": "A" * 1000},
                {"id": "silent_1", "lane": "SILENT", "blob": "S" * 1000},
                *[{"id": f"udm_{i}", "lane": "UDM", "blob": "U" * 4000} for i in range(30)],
            ]
        }
        trimmed_tl = _enforce_timeline_ceiling(huge_tl, max_bytes=25_000)
        self.assertLessEqual(len(json.dumps(trimmed_tl).encode("utf-8")), 25_000)
        self.assertTrue(trimmed_tl.get("events_truncated"))
        remaining_ids = {e["id"] for e in trimmed_tl["events"]}
        self.assertIn("alert_1", remaining_ids)
        self.assertIn("silent_1", remaining_ids)

    def test_layered_coordinates_zero_occlusion_on_dense_graph(self):
        from engine.workflows.case_attack_graph import _assign_layered_coordinates

        dense_nodes = (
            [{"id": f"ip_{i}", "identifier": f"185.220.101.{i}", "node_type": "IP", "is_internal": False, "risk": "malicious"} for i in range(3)]
            + [{"id": f"host_{i}", "identifier": f"host-{i}.corp.local", "node_type": "HOST", "risk": "warning"} for i in range(4)]
            + [{"id": f"user_{i}", "identifier": f"user{i}@corp.local", "node_type": "USER", "risk": "warning"} for i in range(9)]
            + [{"id": f"proc_{i}", "identifier": f"cmd_{i}.exe", "node_type": "PROCESS", "risk": "warning"} for i in range(5)]
            + [{"id": f"rule_{i}", "identifier": f"Silent Rule {i}", "node_type": "RULE", "risk": "warning", "is_alerting": i == 0} for i in range(9)]
            + [{"id": "case_1", "identifier": "Case #109256", "node_type": "CASE", "risk": "info"}]
        )
        edges = [{"from": "ip_0", "to": "host_0"}, {"from": "host_0", "to": "user_0"}, {"from": "user_0", "to": "rule_0"}]
        _assign_layered_coordinates(dense_nodes, edges)

        # Every pair of distinct nodes must have non-overlapping 150x92 bounding boxes
        for idx, a in enumerate(dense_nodes):
            for b in dense_nodes[idx + 1 :]:
                dx = abs(a["x"] - b["x"])
                dy = abs(a["y"] - b["y"])
                self.assertTrue(
                    dx >= 165 or dy >= 100,
                    f"Nodes {a['id']} ({a['x']},{a['y']}) and {b['id']} ({b['x']},{b['y']}) occlude!",
                )


if __name__ == "__main__":
    unittest.main()
