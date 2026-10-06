import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from src.domain import Actor, ConflictError, PermissionDenied, ValidationError
from src.http_api import create_server
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import ALLOCATION_ID_PREFIX, DomainService


class AllocationServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = DomainService(
            SQLiteRepository(Path(self.tmp.name) / "test.db"), RuleEngine()
        )
        self.admin = Actor("admin", "admin")
        self.station = self.service.create(
            self.admin, "station", {"id": "s1", "name": "S", "region": "R"}
        )
        self.assets = {}
        for asset_id in ("a1", "a2", "a3"):
            self.assets[asset_id] = self.service.create(
                self.admin,
                "asset",
                {
                    "id": asset_id,
                    "station_id": "s1",
                    "asset_type": "sensor",
                    "serial_no": asset_id,
                    "last_seen": "2026-10-06",
                    "report_rate": 2,
                },
            )
        self.link = self.service.create(
            self.admin,
            "link",
            {
                "id": "l1",
                "station_id": "s1",
                "asset_id": "a1",
                "link_type": "fiber",
                "capacity": 10,
                "backup_capacity": 3,
            },
        )

    def tearDown(self):
        self.tmp.cleanup()

    def activate_backup(self):
        self.service.transition(self.admin, "l1", "fail", {"reason": "fiber cut"})
        return self.service.transition(self.admin, "l1", "activate_backup", {})

    def entry(self, asset_id):
        allocation = self.service.allocation_for_link("l1")
        return next(
            entry for entry in allocation["data"]["entries"] if entry["asset_id"] == asset_id
        )

    def test_activating_backup_creates_severity_ranked_allocation(self):
        self.activate_backup()
        allocation = self.service.allocation_for_link("l1")
        self.assertEqual(allocation["id"], ALLOCATION_ID_PREFIX + "l1")
        self.assertEqual(allocation["status"], "backup_active")
        self.assertEqual(allocation["data"]["mode"], "backup")
        self.assertEqual(allocation["data"]["epoch"], 1)
        self.assertTrue(allocation["data"]["constrained"])
        self.assertEqual(self.entry("a1"), {
            "asset_id": "a1", "severity": None, "demand": 2, "quota": 2, "state": "active",
        })
        self.assertEqual(self.entry("a2")["state"], "degraded")
        self.assertEqual(self.entry("a2")["quota"], 1)
        self.assertEqual(self.entry("a3")["state"], "queued")
        self.assertEqual(self.entry("a3")["quota"], 0)

    def test_severity_increase_reclaims_quota_immediately(self):
        self.activate_backup()
        # the queued device reports a critical fault and must jump to the head
        incident = self.service.create(self.admin, "incident", {
            "asset_id": "a3", "kind": "leak", "severity": "critical", "summary": "seal failure",
        })
        allocation = self.service.allocation_for_link("l1")
        self.assertEqual(allocation["data"]["epoch"], 2)
        self.assertEqual(self.entry("a3")["state"], "active")
        self.assertEqual(self.entry("a3")["quota"], 2)
        self.assertEqual(self.entry("a1")["state"], "degraded")
        self.assertEqual(self.entry("a2")["state"], "queued")
        # the old plan is gone: entries are recomputed, not appended
        self.assertEqual(len(allocation["data"]["entries"]), 3)

        # escalating yet another device (a2) bumps it ahead of healthy a1
        other = self.service.create(self.admin, "incident", {
            "asset_id": "a2", "kind": "power", "severity": "high", "summary": "brownout",
        })
        allocation = self.service.allocation_for_link("l1")
        self.assertEqual(self.entry("a2")["state"], "degraded")
        self.assertEqual(self.entry("a2")["quota"], 1)
        self.assertEqual(self.entry("a1")["state"], "queued")
        self.service.transition(self.admin, other["id"], "change_severity", {"severity": "low"})
        # lower than critical a3, same level as healthy assets -> order by id again
        self.assertEqual(self.entry("a2")["state"], "degraded")

    def test_severity_change_must_move_and_only_for_active_incident(self):
        incident = self.service.create(self.admin, "incident", {
            "asset_id": "a3", "kind": "leak", "severity": "low", "summary": "x",
        })
        with self.assertRaises(ValidationError):
            self.service.transition(self.admin, incident["id"], "change_severity",
                                    {"severity": "low"})
        with self.assertRaises(ValidationError):
            self.service.transition(self.admin, incident["id"], "change_severity",
                                    {"severity": "apocalyptic"})
        viewer = Actor("viewer", "viewer")
        with self.assertRaises(PermissionDenied):
            self.service.transition(viewer, incident["id"], "change_severity",
                                    {"severity": "high"})

    def test_resolving_incident_recomputes_and_restore_returns_to_normal(self):
        self.activate_backup()
        incident = self.service.create(self.admin, "incident", {
            "asset_id": "a3", "kind": "leak", "severity": "critical", "summary": "x",
        })
        for action in ("diagnose", "plan_recovery", "start_recovery"):
            self.service.transition(self.admin, incident["id"], action, {})
        self.service.transition(self.admin, incident["id"], "resolve", {"summary": "fixed"})
        # critical pressure is gone, plain id ordering returns
        self.assertEqual(self.entry("a1")["state"], "active")
        self.assertEqual(self.entry("a3")["state"], "queued")

        self.service.transition(self.admin, "l1", "restore", {})
        allocation = self.service.allocation_for_link("l1")
        self.assertEqual(allocation["status"], "normal")
        self.assertEqual(allocation["data"]["mode"], "normal")
        self.assertFalse(allocation["data"]["constrained"])
        self.assertTrue(all(e["state"] == "active" and e["quota"] == 2
                            for e in allocation["data"]["entries"]))

    def test_new_asset_registered_during_backup_is_planned_into_allocation(self):
        self.activate_backup()
        self.service.create(self.admin, "asset", {
            "id": "a4", "station_id": "s1", "asset_type": "sensor",
            "serial_no": "a4", "last_seen": "2026-10-06", "report_rate": 1,
        })
        allocation = self.service.allocation_for_link("l1")
        self.assertEqual(self.entry("a4")["state"], "queued")
        self.assertEqual(len(allocation["data"]["entries"]), 4)

    def test_allocation_cannot_be_created_directly(self):
        with self.assertRaises(PermissionDenied):
            self.service.create(self.admin, "allocation", {"link_id": "l1"})

    def test_concurrent_switches_first_writer_wins_loser_sees_plan(self):
        self.service.transition(self.admin, "l1", "fail", {"reason": "cut"})
        version = self.service.get("l1")["version"]
        barrier = threading.Barrier(2)
        outcomes = {}

        def switch(name):
            barrier.wait()
            try:
                updated = self.service.transition(
                    Actor("dispatch-" + name, "operator"),
                    "l1", "activate_backup", {}, expected_version=version,
                )
                outcomes[name] = ("won", updated["version"])
            except ConflictError as exc:
                details = exc.details
                outcomes[name] = (
                    "lost",
                    details["allocation"]["status"],
                    details["allocation"]["data"]["mode"],
                )

        threads = [threading.Thread(target=switch, args=(n,)) for n in ("one", "two")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len([v for v in outcomes.values() if v[0] == "won"]), 1)
        loser = next(v for v in outcomes.values() if v[0] == "lost")
        self.assertEqual(loser[1:], ("backup_active", "backup"))

    def test_repeated_switch_returns_current_allocation(self):
        self.activate_backup()
        with self.assertRaises(ConflictError) as caught:
            self.service.transition(self.admin, "l1", "activate_backup", {})
        details = caught.exception.details
        self.assertEqual(details["link_id"], "l1")
        self.assertEqual(details["allocation"]["data"]["mode"], "backup")


class AllocationHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        service = DomainService(
            SQLiteRepository(Path(self.tmp.name) / "http.db"), RuleEngine()
        )
        static_dir = str(Path(__file__).resolve().parent.parent / "static")
        server = create_server("127.0.0.1", 0, service, RuleEngine(), static_dir)
        self.port = server.server_address[1]
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()
        self.server = server
        self.service = service

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        payload = None
        hdrs = dict(headers or {})
        if body is not None:
            import json
            payload = json.dumps(body)
            hdrs["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=hdrs)
        response = connection.getresponse()
        import json
        parsed = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, parsed

    def admin_headers(self):
        return {"X-User-Id": "admin", "X-Role": "admin"}

    def test_concurrent_switch_over_http_loser_reads_current_plan(self):
        self.request("POST", "/api/stations",
                     {"id": "s1", "name": "S", "region": "R"}, self.admin_headers())
        self.request("POST", "/api/assets",
                     {"id": "a1", "station_id": "s1", "asset_type": "sensor",
                      "serial_no": "a1", "last_seen": "t"}, self.admin_headers())
        status, link = self.request("POST", "/api/links",
                                    {"id": "l1", "station_id": "s1", "asset_id": "a1",
                                     "link_type": "fiber", "capacity": 10,
                                     "backup_capacity": 1}, self.admin_headers())
        self.assertEqual(status, 201)
        version = link["version"]
        self.request("POST", "/api/entities/l1/actions",
                     {"action": "fail", "data": {"reason": "cut"}}, self.admin_headers())
        version = self.service.get("l1")["version"]

        barrier = threading.Barrier(2)
        results = {}

        def switch(name):
            barrier.wait()
            status_code, payload = self.request(
                "POST", "/api/entities/l1/actions",
                {"action": "activate_backup", "data": {}, "expected_version": version},
                {"X-User-Id": "dispatcher-" + name, "X-Role": "operator"},
            )
            results[name] = (status_code, payload)

        threads = [threading.Thread(target=switch, args=(n,)) for n in ("one", "two")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        statuses = sorted(code for code, _ in results.values())
        self.assertEqual(statuses, [200, 409])
        loser = next(payload for code, payload in results.values() if code == 409)
        self.assertEqual(loser["type"], "ConflictError")
        self.assertEqual(loser["details"]["allocation"]["status"], "backup_active")
        self.assertEqual(loser["details"]["allocation"]["data"]["mode"], "backup")

        # the loser then reads the same plan through the query API
        status, payload = self.request("GET", "/api/allocations?link_id=l1")
        self.assertEqual(status, 200)
        self.assertEqual(payload["items"][0]["data"]["epoch"], 1)


if __name__ == "__main__":
    unittest.main()
