import json
import tempfile
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from src.domain import Actor, ConflictError
from src.http_api import create_server
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class BackupAllocationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = DomainService(SQLiteRepository(Path(self.tmp.name) / "test.db"), RuleEngine())
        self.admin = Actor("admin", "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def _make_station_assets_link(self, backup_capacity=15, asset_count=3, reporting_rate=10):
        station = self.service.create(self.admin, "station", {"name": "S", "region": "R"})
        assets = []
        for i in range(asset_count):
            assets.append(self.service.create(self.admin, "asset", {
                "station_id": station["id"],
                "asset_type": "sensor",
                "serial_no": "A%d" % i,
                "last_seen": "x",
                "reporting_rate": reporting_rate,
            }))
        link = self.service.create(self.admin, "link", {
            "station_id": station["id"],
            "asset_id": assets[0]["id"],
            "link_type": "fiber",
            "capacity": 100,
            "backup_capacity": backup_capacity,
        })
        return station, assets, link

    def _states(self, allocation):
        return {item["asset_id"]: item["state"] for item in allocation["data"]["items"]}

    def test_severity_based_allocation(self):
        station, assets, link = self._make_station_assets_link(backup_capacity=15)
        a1, a2, a3 = assets
        self.service.create(self.admin, "incident", {
            "station_id": station["id"], "asset_id": a3["id"], "kind": "loss",
            "severity": "critical", "summary": "x",
        })
        self.service.create(self.admin, "incident", {
            "station_id": station["id"], "asset_id": a1["id"], "kind": "loss",
            "severity": "low", "summary": "x",
        })
        self.service.transition(self.admin, link["id"], "fail", {"reason": "cut"})
        allocation = self.service.list("backup_allocation")[0]
        states = self._states(allocation)
        self.assertEqual(states[a3["id"]], "granted")
        self.assertEqual(states[a1["id"]], "degraded")
        self.assertEqual(states[a2["id"]], "queued")

    def test_severity_rise_restores_quota(self):
        station, assets, link = self._make_station_assets_link(backup_capacity=15)
        a1, a2, a3 = assets
        self.service.create(self.admin, "incident", {
            "station_id": station["id"], "asset_id": a3["id"], "kind": "loss",
            "severity": "critical", "summary": "x",
        })
        inc1 = self.service.create(self.admin, "incident", {
            "station_id": station["id"], "asset_id": a1["id"], "kind": "loss",
            "severity": "low", "summary": "x",
        })
        self.service.transition(self.admin, link["id"], "fail", {"reason": "cut"})
        self.assertEqual(self._states(self.service.list("backup_allocation")[0])[a1["id"]], "degraded")
        # a1 rises to critical -> immediately takes its quota back
        self.service.transition(self.admin, inc1["id"], "change_severity", {"severity": "critical"})
        states = self._states(self.service.list("backup_allocation")[0])
        self.assertEqual(states[a1["id"]], "granted")
        self.assertEqual(states[a3["id"]], "degraded")
        self.assertEqual(states[a2["id"]], "queued")

    def test_severity_fall_recomputes(self):
        station, assets, link = self._make_station_assets_link(backup_capacity=15)
        a1, a2, a3 = assets
        inc3 = self.service.create(self.admin, "incident", {
            "station_id": station["id"], "asset_id": a3["id"], "kind": "loss",
            "severity": "critical", "summary": "x",
        })
        self.service.create(self.admin, "incident", {
            "station_id": station["id"], "asset_id": a1["id"], "kind": "loss",
            "severity": "high", "summary": "x",
        })
        self.service.transition(self.admin, link["id"], "fail", {"reason": "cut"})
        # a3 critical (granted), a1 high (degraded)
        states = self._states(self.service.list("backup_allocation")[0])
        self.assertEqual(states[a3["id"]], "granted")
        self.assertEqual(states[a1["id"]], "degraded")
        # a3 falls to low -> loses priority to a1, gets degraded
        self.service.transition(self.admin, inc3["id"], "change_severity", {"severity": "low"})
        states = self._states(self.service.list("backup_allocation")[0])
        self.assertEqual(states[a1["id"]], "granted")
        self.assertEqual(states[a3["id"]], "degraded")

    def test_restore_clears_allocation(self):
        station, assets, link = self._make_station_assets_link(backup_capacity=15)
        self.service.transition(self.admin, link["id"], "fail", {"reason": "cut"})
        self.assertEqual(self.service.list("backup_allocation")[0]["status"], "active")
        self.service.transition(self.admin, link["id"], "restore", {})
        allocation = self.service.list("backup_allocation")[0]
        self.assertEqual(allocation["status"], "normal")
        self.assertEqual(allocation["data"]["items"], [])

    def test_concurrent_switch_first_write_wins(self):
        station, assets, link = self._make_station_assets_link(backup_capacity=15)
        a1 = assets[0]
        self.service.create(self.admin, "incident", {
            "station_id": station["id"], "asset_id": a1["id"], "kind": "loss",
            "severity": "high", "summary": "x",
        })
        self.service.transition(self.admin, link["id"], "fail", {"reason": "cut"})
        stale_version = self.service.get(link["id"])["version"]
        alice = Actor("alice", "operator")
        bob = Actor("bob", "operator")
        # Alice submits first -> wins
        won = self.service.transition(alice, link["id"], "activate_backup", {}, expected_version=stale_version)
        self.assertEqual(won["status"], "backup_active")
        # Bob submits with the same stale version -> loses, but sees current allocation
        with self.assertRaises(ConflictError) as ctx:
            self.service.transition(bob, link["id"], "activate_backup", {}, expected_version=stale_version)
        self.assertIsNotNone(ctx.exception.current)
        self.assertEqual(ctx.exception.current["link"]["version"], won["version"])
        self.assertEqual(ctx.exception.current["allocation"]["status"], "active")
        states = self._states(ctx.exception.current["allocation"])
        self.assertEqual(states[a1["id"]], "granted")


class BackupAllocationHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = DomainService(SQLiteRepository(Path(self.tmp.name) / "test.db"), RuleEngine())
        self.admin = Actor("admin", "admin")
        static_dir = str(Path(__file__).resolve().parent.parent / "static")
        self.server = create_server("127.0.0.1", 0, self.service, self.service.rules, static_dir)
        self.port = self.server.server_address[1]
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_concurrent_switch_conflict_includes_current_allocation(self):
        station = self.service.create(self.admin, "station", {"name": "S", "region": "R"})
        a1 = self.service.create(self.admin, "asset", {
            "station_id": station["id"], "asset_type": "sensor",
            "serial_no": "A1", "last_seen": "x", "reporting_rate": 10,
        })
        link = self.service.create(self.admin, "link", {
            "station_id": station["id"], "asset_id": a1["id"],
            "link_type": "fiber", "capacity": 100, "backup_capacity": 15,
        })
        self.service.transition(self.admin, link["id"], "fail", {"reason": "cut"})
        stale_version = self.service.get(link["id"])["version"]
        switch_body = {"action": "activate_backup", "data": {}, "expected_version": stale_version}
        # Alice (via HTTP) submits first -> wins
        status, body = self._request(
            "POST", "/api/entities/%s/actions" % link["id"], switch_body,
            {"X-User-Id": "alice", "X-Role": "operator"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "backup_active")
        # Bob (via HTTP) submits with the same stale version -> 409, sees current allocation
        status, body = self._request(
            "POST", "/api/entities/%s/actions" % link["id"], switch_body,
            {"X-User-Id": "bob", "X-Role": "operator"},
        )
        self.assertEqual(status, 409)
        self.assertIn("current", body)
        self.assertEqual(body["current"]["link"]["status"], "backup_active")
        self.assertEqual(body["current"]["allocation"]["status"], "active")
        states = {item["asset_id"]: item["state"] for item in body["current"]["allocation"]["data"]["items"]}
        self.assertEqual(states[a1["id"]], "granted")


if __name__ == "__main__":
    unittest.main()
