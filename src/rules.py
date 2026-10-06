from datetime import datetime, timedelta

from .domain import ConflictError, InvalidTransition, PermissionDenied, ValidationError


def _require(data, fields):
    for field in fields:
        value = data.get(field)
        if value is None or value == "" or value == [] or value == {}:
            raise ValidationError("missing required field: " + field)


def _ensure_role(actor, allowed):
    if "*" not in allowed and actor.role not in allowed:
        raise PermissionDenied("role %s is not allowed here" % actor.role)


def _all(lookup, kind):
    return lookup(kind, "*", None) or [] if lookup else []


def _find_one(lookup, kind, field, value):
    rows = lookup(kind, field, value) or [] if lookup else []
    return rows[0] if rows else None


def _number(value, field):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValidationError(field + " must be numeric")
    if number < 0:
        raise ValidationError(field + " must be non-negative")
    return number


def _validate_asset(data, lookup):
    if not _find_one(lookup, "station", "id", data.get("station_id")):
        raise ValidationError("asset requires station")
    if data.get("clock_offset_seconds") not in (None, ""):
        _number(data.get("clock_offset_seconds"), "clock_offset_seconds")
    if data.get("report_rate") not in (None, ""):
        report_rate = _number(data.get("report_rate"), "report_rate")
        if report_rate <= 0:
            raise ValidationError("report_rate must be positive")


def _validate_link(data, lookup):
    if not _find_one(lookup, "station", "id", data.get("station_id")):
        raise ValidationError("link requires station")
    if not _find_one(lookup, "asset", "id", data.get("asset_id")):
        raise ValidationError("link requires asset")
    capacity = _number(data.get("capacity"), "capacity")
    if data.get("backup_capacity") not in (None, ""):
        backup = _number(data.get("backup_capacity"), "backup_capacity")
        if backup > capacity:
            raise ValidationError("backup_capacity cannot exceed capacity")


def _validate_telemetry(data, lookup):
    asset = _find_one(lookup, "asset", "id", data.get("asset_id"))
    if not asset:
        raise ValidationError("telemetry requires asset")
    _number(data.get("value"), "value")
    try:
        revision = int(data.get("revision"))
    except (TypeError, ValueError):
        raise ValidationError("revision must be an integer")
    if revision < 1:
        raise ValidationError("revision must be positive")
    for item in _all(lookup, "telemetry"):
        if item["data"].get("asset_id") == data.get("asset_id") and item["data"].get("metric") == data.get("metric"):
            if int(item["data"].get("revision", 0)) >= revision:
                raise ConflictError("telemetry revision must increase")


def _validate_incident(data, lookup):
    if not data.get("station_id") and not data.get("asset_id") and not data.get("link_id"):
        raise ValidationError("incident requires station_id, asset_id or link_id")
    if data.get("severity") not in ("low", "medium", "high", "critical"):
        raise ValidationError("invalid incident severity")
    for item in _all(lookup, "incident"):
        if item["status"] in ("open", "diagnosing", "recovery_planned", "recovering") and item["data"].get("asset_id") == data.get("asset_id") and item["data"].get("kind") == data.get("kind"):
            raise ConflictError("active incident already exists for asset and kind")


def _validate_action(data, lookup):
    incident = _find_one(lookup, "incident", "id", data.get("incident_id"))
    if not incident or incident["status"] in ("resolved", "closed"):
        raise ValidationError("recovery action requires an active incident")
    if data.get("action_type") not in ("remote_restart", "switch_backup", "firmware_rollback", "dispatch_mission"):
        raise ValidationError("invalid action_type")
    key = data.get("dedupe_key")
    for item in _all(lookup, "recovery_action"):
        if item["data"].get("dedupe_key") == key and item["status"] not in ("succeeded", "failed", "cancelled"):
            raise ConflictError("active recovery action already exists for dedupe_key")


def _validate_mission(data, lookup):
    if not _find_one(lookup, "station", "id", data.get("station_id")):
        raise ValidationError("mission requires station")
    if not data.get("window_start") or not data.get("window_end"):
        raise ValidationError("mission window is required")


def _validate_gap(data, lookup):
    if not _find_one(lookup, "incident", "id", data.get("incident_id")):
        raise ValidationError("data gap requires incident")
    if not data.get("start_at") or not data.get("end_at"):
        raise ValidationError("gap window is required")


def _revise_telemetry(actor, entity, data, lookup):
    try:
        new_revision = int(data.get("revision"))
    except (TypeError, ValueError):
        raise ValidationError("revision must be an integer")
    if new_revision <= int(entity["data"].get("revision", 0)):
        raise ConflictError("late revision must increase revision number")
    return {"late_revision": True, "revised_by": actor.user_id}


def _change_incident_severity(actor, entity, data, lookup):
    new_severity = data.get("severity")
    if new_severity not in ("low", "medium", "high", "critical"):
        raise ValidationError("invalid incident severity")
    if new_severity == entity["data"].get("severity"):
        raise ValidationError("incident severity is unchanged")
    return {"previous_severity": entity["data"].get("severity"), "severity": new_severity, "changed_by": actor.user_id}


def _resolve_incident(actor, entity, data, lookup):
    actions = [a for a in _all(lookup, "recovery_action") if a["data"].get("incident_id") == entity["id"] and a["status"] not in ("succeeded", "failed", "cancelled")]
    if actions:
        raise ConflictError("incident cannot resolve while recovery actions are active")
    gaps = [g for g in _all(lookup, "gap") if g["data"].get("incident_id") == entity["id"] and g["status"] not in ("filled", "accepted", "closed")]
    if gaps:
        raise ConflictError("incident cannot resolve while data gaps remain open")
    assets = [a for a in _all(lookup, "asset") if a["status"] in ("faulty", "offline", "rebooting")]
    if entity["data"].get("asset_id") and any(a["id"] == entity["data"].get("asset_id") for a in assets):
        raise ConflictError("affected asset is still unavailable")
    return {"resolved_by": actor.user_id}


def _complete_action(actor, entity, data, lookup):
    if not data.get("outcome"):
        raise ValidationError("outcome is required")
    return {"completed_by": actor.user_id}


def _complete_mission(actor, entity, data, lookup):
    if not data.get("report"):
        raise ValidationError("report is required")
    return {"completed_by": actor.user_id}


class RuleEngine:
    ALIASES = {
        "stations": "station", "assets": "asset", "links": "link", "telemetries": "telemetry",
        "incidents": "incident", "recovery_actions": "recovery_action", "missions": "mission",
        "gaps": "gap", "allocations": "allocation",
    }
    INITIAL_STATUS = {
        "station": "online", "asset": "healthy", "link": "up", "telemetry": "current",
        "incident": "open", "recovery_action": "proposed", "mission": "planned", "gap": "open",
        "allocation": "normal",
    }
    # active incidents are those that have not been resolved/closed yet
    ACTIVE_INCIDENT_STATUSES = ("open", "diagnosing", "recovery_planned", "recovering")
    SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}
    # when a link does not declare backup_capacity, the backup carries this share of capacity
    DEFAULT_BACKUP_RATIO = 0.25
    TRANSITIONS = {
        "station": {
            "degrade": (("online",), "degraded"),
            "go_offline": (("online", "degraded"), "offline"),
            "resume": (("degraded", "offline"), "online"),
        },
        "asset": {
            "degrade": (("healthy",), "degraded"),
            "fail": (("healthy", "degraded"), "faulty"),
            "start_reboot": (("faulty",), "rebooting"),
            "finish_reboot": (("rebooting",), "healthy"),
            "restore": (("faulty",), "healthy"),
        },
        "link": {
            "degrade": (("up",), "degraded"),
            "fail": (("up", "degraded"), "down"),
            "activate_backup": (("down", "degraded"), "backup_active"),
            "restore": (("down", "backup_active", "degraded"), "up"),
        },
        "telemetry": {
            "mark_stale": (("current",), "stale"),
            "quarantine": (("current", "stale"), "quarantined"),
            "revise": (("current", "stale", "quarantined"), "current"),
            "clear": (("stale",), "current"),
        },
        "incident": {
            "diagnose": (("open",), "diagnosing"),
            "plan_recovery": (("diagnosing",), "recovery_planned"),
            "start_recovery": (("recovery_planned",), "recovering"),
            "resolve": (("recovering",), "resolved"),
            "close": (("resolved",), "closed"),
            "reopen": (("resolved", "closed"), "open"),
            "change_severity": (
                ("open", "diagnosing", "recovery_planned", "recovering"),
                None,
            ),
        },
        "recovery_action": {
            "approve": (("proposed",), "approved"),
            "start": (("approved",), "running"),
            "succeed": (("running",), "succeeded"),
            "fail": (("running",), "failed"),
            "cancel": (("proposed", "approved", "running"), "cancelled"),
        },
        "mission": {
            "approve": (("planned",), "approved"),
            "depart": (("approved",), "underway"),
            "complete": (("underway",), "completed"),
            "cancel": (("planned", "approved", "underway"), "cancelled"),
        },
        "gap": {
            "estimate": (("open",), "estimated"),
            "fill": (("estimated",), "filled"),
            "accept": (("filled", "open"), "accepted"),
        },
    }
    CREATE_REQUIRED = {
        "station": ("name", "region"),
        "asset": ("station_id", "asset_type", "serial_no", "last_seen"),
        "link": ("station_id", "asset_id", "link_type", "capacity"),
        "telemetry": ("asset_id", "metric", "value", "observed_at", "revision"),
        "incident": ("kind", "severity", "summary"),
        "recovery_action": ("incident_id", "action_type", "dedupe_key"),
        "mission": ("station_id", "purpose", "window_start", "window_end"),
        "gap": ("incident_id", "start_at", "end_at"),
    }
    ACTION_REQUIRED = {
        ("station", "degrade"): ("reason",),
        ("link", "fail"): ("reason",),
        ("telemetry", "revise"): ("revision",),
        ("recovery_action", "succeed"): ("outcome",),
        ("mission", "complete"): ("report",),
        ("gap", "fill"): ("estimate",),
        ("incident", "resolve"): ("summary",),
        ("incident", "change_severity"): ("severity",),
    }
    CREATE_ROLES = {
        "station": ("admin", "engineer"),
        "asset": ("admin", "engineer"),
        "link": ("admin", "engineer"),
        "telemetry": ("admin", "operator", "engineer"),
        "incident": ("admin", "operator", "engineer"),
        "recovery_action": ("admin", "operator", "engineer"),
        "mission": ("admin", "engineer"),
        "gap": ("admin", "operator", "engineer"),
        # allocations are computed by the system, never created through the API
        "allocation": (),
    }
    ROLE_ACTIONS = {
        "degrade": ("admin", "engineer", "operator"),
        "go_offline": ("admin", "engineer", "operator"),
        "resume": ("admin", "engineer", "operator"),
        "fail": ("admin", "engineer", "operator"),
        "start_reboot": ("admin", "engineer", "operator"),
        "finish_reboot": ("admin", "engineer", "operator"),
        "restore": ("admin", "engineer", "operator"),
        "activate_backup": ("admin", "engineer", "operator"),
        "mark_stale": ("admin", "operator", "engineer"),
        "quarantine": ("admin", "engineer", "operator"),
        "revise": ("admin", "operator", "engineer"),
        "clear": ("admin", "operator", "engineer"),
        "diagnose": ("admin", "operator", "engineer"),
        "plan_recovery": ("admin", "operator", "engineer"),
        "start_recovery": ("admin", "operator", "engineer"),
        "resolve": ("admin", "engineer"),
        "close": ("admin", "engineer"),
        "reopen": ("admin", "engineer", "operator"),
        "change_severity": ("admin", "engineer", "operator"),
        "approve": ("admin", "engineer"),
        "start": ("admin", "engineer", "operator"),
        "succeed": ("admin", "engineer", "operator"),
        "cancel": ("admin", "engineer", "operator"),
        "depart": ("admin", "engineer", "operator"),
        "estimate": ("admin", "engineer", "operator"),
        "fill": ("admin", "engineer", "operator"),
        "accept": ("admin", "engineer", "operator"),
    }
    CUSTOM_CREATE = {
        "asset": lambda a, d, l: _validate_asset(d, l),
        "link": lambda a, d, l: _validate_link(d, l),
        "telemetry": lambda a, d, l: _validate_telemetry(d, l),
        "incident": lambda a, d, l: _validate_incident(d, l),
        "recovery_action": lambda a, d, l: _validate_action(d, l),
        "mission": lambda a, d, l: _validate_mission(d, l),
        "gap": lambda a, d, l: _validate_gap(d, l),
    }
    CUSTOM_TRANSITIONS = {
        ("telemetry", "revise"): _revise_telemetry,
        ("incident", "resolve"): _resolve_incident,
        ("incident", "change_severity"): _change_incident_severity,
        ("recovery_action", "succeed"): _complete_action,
        ("mission", "complete"): _complete_mission,
    }

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind, data=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        _ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        _require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = self.CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition("cannot %s from status %s" % (action, entity["status"]))
        allowed = self.ROLE_ACTIONS.get((kind, action), self.ROLE_ACTIONS.get(action, ("admin",)))
        _ensure_role(actor, allowed)
        _require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = self.CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        # next_status of None means the action changes data but keeps the entity status
        if next_status is None:
            next_status = entity["status"]
        return next_status, patch

    @staticmethod
    def _asset_demand(asset):
        data = asset.get("data", {})
        rate = data.get("report_rate")
        if rate in (None, ""):
            return 1.0
        return max(float(rate), 0.0)

    @staticmethod
    def _incident_applies(incident, link, asset):
        data = incident.get("data", {})
        asset_id = data.get("asset_id")
        if asset_id:
            return asset_id == asset["id"]
        # link- and station-scoped incidents cover every asset on that link
        link_id = data.get("link_id")
        if link_id:
            return link_id == link["id"]
        station_id = data.get("station_id")
        if station_id:
            return station_id == link["data"].get("station_id")
        return False

    def asset_severity(self, asset, link, incidents):
        """Highest active-incident severity affecting an asset on this link."""
        ranks = [
            incident["data"].get("severity")
            for incident in incidents
            if incident["status"] in self.ACTIVE_INCIDENT_STATUSES
            and self._incident_applies(incident, link, asset)
        ]
        if not ranks:
            return None
        return max(ranks, key=lambda severity: self.SEVERITY_RANK.get(severity, 0))

    def backup_capacity(self, link):
        data = link.get("data", {})
        if data.get("backup_capacity") not in (None, ""):
            return max(float(data["backup_capacity"]), 0.0)
        return float(data.get("capacity", 0)) * self.DEFAULT_BACKUP_RATIO

    def build_backup_allocation(self, link, assets, incidents):
        """Grant the limited backup channel by severity, highest first.

        Higher-severity assets get their full report rate; when capacity runs
        out, lower-severity assets are degraded (partial quota) or queued
        (zero quota) so critical readings are never squeezed out.
        """
        capacity = round(self.backup_capacity(link), 6)
        ranked = sorted(
            [
                {
                    "asset_id": asset["id"],
                    "severity": self.asset_severity(asset, link, incidents),
                    "demand": self._asset_demand(asset),
                }
                for asset in assets
                if asset["data"].get("station_id") == link["data"].get("station_id")
            ],
            key=lambda item: (-self.SEVERITY_RANK.get(item["severity"], 0), item["asset_id"]),
        )
        entries = []
        remaining = capacity
        for item in ranked:
            quota = round(min(item["demand"], max(remaining, 0.0)), 6)
            if quota + 1e-9 >= item["demand"]:
                state = "active"
            elif quota > 1e-9:
                state = "degraded"
            else:
                state = "queued"
            entries.append(
                {
                    "asset_id": item["asset_id"],
                    "severity": item["severity"],
                    "demand": round(item["demand"], 6),
                    "quota": quota,
                    "state": state,
                }
            )
            remaining = max(remaining - item["demand"], 0.0)
        queued = [entry for entry in entries if entry["state"] == "queued"]
        degraded = [entry for entry in entries if entry["state"] == "degraded"]
        # queue head is the first to be squeezed; within the same severity ids
        # are ordered deterministically so two recomputations compare cleanly
        for pos, entry in enumerate(sorted(degraded + queued, key=self._queue_sort_key), start=1):
            entry["queue_position"] = pos
        total_demand = round(sum(item["demand"] for item in ranked), 6)
        return {
            "mode": "backup",
            "link_id": link["id"],
            "capacity": capacity,
            "total_demand": total_demand,
            "constrained": total_demand > capacity + 1e-9,
            "entries": entries,
        }

    @staticmethod
    def _queue_sort_key(entry):
        rank = RuleEngine.SEVERITY_RANK.get(entry["severity"], 0)
        return (rank, entry["asset_id"])

    def build_normal_allocation(self, link, assets):
        """Routine allocation once the main link is restored."""
        entries = [
            {
                "asset_id": asset["id"],
                "severity": None,
                "demand": round(self._asset_demand(asset), 6),
                "quota": round(self._asset_demand(asset), 6),
                "state": "active",
            }
            for asset in assets
            if asset["data"].get("station_id") == link["data"].get("station_id")
        ]
        entries.sort(key=lambda entry: entry["asset_id"])
        return {
            "mode": "normal",
            "link_id": link["id"],
            "capacity": round(float(link["data"].get("capacity", 0)), 6),
            "total_demand": round(sum(entry["demand"] for entry in entries), 6),
            "constrained": False,
            "entries": entries,
        }
