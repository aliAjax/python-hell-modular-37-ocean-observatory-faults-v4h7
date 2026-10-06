import unittest

from src.rules import RuleEngine


def link(link_id="l1", capacity=10, backup_capacity=3, station_id="s1"):
    return {
        "id": link_id,
        "kind": "link",
        "status": "backup_active",
        "data": {
            "station_id": station_id,
            "capacity": capacity,
            "backup_capacity": backup_capacity,
        },
    }


def asset(asset_id, station_id="s1", report_rate=2):
    return {
        "id": asset_id,
        "kind": "asset",
        "status": "healthy",
        "data": {"station_id": station_id, "report_rate": report_rate},
    }


def incident(incident_id, asset_id=None, station_id=None, link_id=None,
             severity="high", status="open"):
    data = {"kind": "leak", "severity": severity, "summary": "x"}
    if asset_id:
        data["asset_id"] = asset_id
    if station_id:
        data["station_id"] = station_id
    if link_id:
        data["link_id"] = link_id
    return {"id": incident_id, "kind": "incident", "status": status, "data": data}


class AllocationRulesTest(unittest.TestCase):
    def setUp(self):
        self.rules = RuleEngine()

    def test_capacity_pressure_hits_low_severity_first(self):
        lnk = link()
        assets = [asset("a1"), asset("a2"), asset("a3")]
        incidents = [incident("i1", asset_id="a1", severity="critical")]
        plan = self.rules.build_backup_allocation(lnk, assets, incidents)
        by_asset = {entry["asset_id"]: entry for entry in plan["entries"]}
        self.assertTrue(plan["constrained"])
        self.assertEqual(by_asset["a1"]["state"], "active")
        self.assertEqual(by_asset["a1"]["quota"], 2)
        self.assertEqual(by_asset["a2"]["state"], "degraded")
        self.assertEqual(by_asset["a2"]["quota"], 1)
        self.assertEqual(by_asset["a3"]["state"], "queued")
        self.assertEqual(by_asset["a3"]["quota"], 0)
        # queue head is the first asset to be squeezed
        self.assertEqual(by_asset["a2"]["queue_position"], 1)
        self.assertEqual(by_asset["a3"]["queue_position"], 2)

    def test_entries_are_ordered_by_severity_then_id(self):
        lnk = link(backup_capacity=10)
        assets = [asset("a3", report_rate=1), asset("a1", report_rate=1), asset("a2", report_rate=1)]
        incidents = [
            incident("i1", asset_id="a2", severity="high"),
            incident("i2", asset_id="a1", severity="critical"),
        ]
        plan = self.rules.build_backup_allocation(lnk, assets, incidents)
        self.assertEqual(
            [(e["asset_id"], e["severity"]) for e in plan["entries"]],
            [("a1", "critical"), ("a2", "high"), ("a3", None)],
        )
        self.assertFalse(plan["constrained"])
        self.assertTrue(all(e["state"] == "active" for e in plan["entries"]))

    def test_resolved_incidents_do_not_set_severity(self):
        lnk = link()
        assets = [asset("a1", report_rate=1), asset("a2", report_rate=1)]
        incidents = [incident("i1", asset_id="a2", severity="critical", status="resolved")]
        plan = self.rules.build_backup_allocation(lnk, assets, incidents)
        self.assertTrue(all(e["severity"] is None for e in plan["entries"]))

    def test_station_scoped_incident_covers_all_station_assets(self):
        lnk = link()
        assets = [asset("a1", report_rate=1), asset("a2", report_rate=1)]
        incidents = [incident("i1", station_id="s1", severity="medium")]
        plan = self.rules.build_backup_allocation(lnk, assets, incidents)
        self.assertTrue(all(e["severity"] == "medium" for e in plan["entries"]))

    def test_other_station_assets_are_excluded(self):
        lnk = link(station_id="s1")
        assets = [asset("a1", station_id="s1", report_rate=1), asset("a9", station_id="s2", report_rate=1)]
        plan = self.rules.build_backup_allocation(lnk, assets, [])
        self.assertEqual([e["asset_id"] for e in plan["entries"]], ["a1"])

    def test_default_backup_capacity_is_a_quarter_of_main_capacity(self):
        lnk = link(backup_capacity=None, capacity=8)
        plan = self.rules.build_backup_allocation(lnk, [], [])
        self.assertEqual(plan["capacity"], 2)

    def test_normal_allocation_restores_full_quotas(self):
        lnk = link(backup_capacity=3)
        assets = [asset("a1"), asset("a2"), asset("a3")]
        plan = self.rules.build_normal_allocation(lnk, assets)
        self.assertEqual(plan["mode"], "normal")
        self.assertFalse(plan["constrained"])
        self.assertTrue(all(e["state"] == "active" and e["quota"] == 2 for e in plan["entries"]))
        self.assertEqual([e["asset_id"] for e in plan["entries"]], ["a1", "a2", "a3"])


if __name__ == "__main__":
    unittest.main()
