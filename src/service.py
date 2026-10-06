import hashlib
from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .rules import RuleEngine


# Severity weights used to prioritise assets when the backup channel is
# capacity-constrained. Higher weight = higher priority = first to be
# granted its full reporting quota.
_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_DEFAULT_REPORTING_RATE = 10
_ACTIVE_INCIDENT_STATUSES = ("open", "diagnosing", "recovery_planned", "recovering")


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind, payload)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        if expected != entity["version"]:
            # A lost optimistic-concurrency race. Detect it before validating
            # the transition (the status may have moved on), so the caller
            # sees a clean conflict. Link switchers additionally get the
            # current allocation the first write produced.
            current = self.repository.get_entity(entity_id)
            current_state = None
            if entity["kind"] == "link" and action in ("activate_backup", "fail"):
                current_state = {"link": current, "allocation": self._find_allocation(entity_id)}
            raise ConflictError(
                "version conflict: expected %s, found %s" % (expected, entity["version"]),
                current=current_state,
            )
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        try:
            updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        except ConflictError as exc:
            if entity["kind"] == "link" and action in ("activate_backup", "fail"):
                current = self.repository.get_entity(entity_id)
                exc.current = {
                    "link": current,
                    "allocation": self._find_allocation(entity_id),
                }
            raise
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        if entity["kind"] == "link":
            if action in ("activate_backup", "fail"):
                self._activate_backup(actor, updated)
            elif action == "restore":
                self._clear_backup(actor, updated)
        elif entity["kind"] == "incident" and action == "change_severity":
            old_weight = _SEVERITY_WEIGHT.get(entity["data"].get("severity"), 0)
            new_weight = _SEVERITY_WEIGHT.get(updated["data"].get("severity"), 0)
            risen_asset_id = updated["data"].get("asset_id") if new_weight > old_weight else None
            self._recompute_for_incident(actor, updated, risen_asset_id, new_weight)
        return updated

    def merge_offline(self, actor, records):
        """Merge field records by a stable (source_id, record_id) identity."""
        if not isinstance(records, list):
            raise ValidationError("records must be a list")
        created = []
        for raw in records:
            if not isinstance(raw, dict):
                raise ValidationError("each offline record must be an object")
            source_id = str(raw.get("source_id", "")).strip()
            record_id = str(raw.get("record_id", "")).strip()
            if not source_id or not record_id:
                raise ValidationError("source_id and record_id are required")
            digest = hashlib.sha256((source_id + "\0" + record_id).encode("utf-8")).hexdigest()[:32]
            entity_id = "offline-" + digest
            existing = self.repository.get_entity(entity_id)
            if existing:
                created.append(existing)
                continue
            payload = dict(raw)
            self.rules.validate_create(actor, "offline_record", payload, self._lookup)
            entity = self.repository.create_entity(
                entity_id,
                "offline_record",
                self.rules.initial_status("offline_record", payload),
                payload,
                actor.user_id,
            )
            self.audit.record(entity_id, actor, "merge_offline", None, entity["status"], {"source_id": source_id, "record_id": record_id})
            created.append(entity)
        return created

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def _find_allocation(self, link_id):
        for allocation in self.list("backup_allocation"):
            if allocation["data"].get("link_id") == link_id:
                return allocation
        return None

    def _compute_backup_items(self, link, risen_asset_id=None, risen_priority=None):
        """Allocate the backup channel capacity among the station's assets.

        Assets with active incidents are prioritised by severity weight; the
        greedy fill grants each asset its full reporting demand until the
        capacity runs out, so lower-severity assets are the first to be
        degraded or queued. When an asset's severity has just risen, that
        asset is boosted ahead of same-priority assets so it immediately
        takes its quota back. Returns ``(items, capacity)``.
        """
        station_id = link["data"].get("station_id")
        try:
            capacity = float(link["data"].get("backup_capacity", 0) or 0)
        except (TypeError, ValueError):
            capacity = 0.0
        assets = [a for a in self.list("asset") if a["data"].get("station_id") == station_id]
        priority = {}
        severity_of = {}
        for incident in self.list("incident"):
            if incident["status"] not in _ACTIVE_INCIDENT_STATUSES:
                continue
            asset_id = incident["data"].get("asset_id")
            if not asset_id or not any(a["id"] == asset_id for a in assets):
                continue
            weight = _SEVERITY_WEIGHT.get(incident["data"].get("severity"), 0)
            if weight > priority.get(asset_id, 0):
                priority[asset_id] = weight
                severity_of[asset_id] = incident["data"].get("severity")
        assets.sort(key=lambda a: (
            -priority.get(a["id"], 0),
            -(1 if a["id"] == risen_asset_id else 0),
            a["id"],
        ))
        items = []
        remaining = capacity
        for asset in assets:
            try:
                demand = float(asset["data"].get("reporting_rate", _DEFAULT_REPORTING_RATE) or 0)
            except (TypeError, ValueError):
                demand = 0.0
            granted = min(demand, remaining)
            remaining -= granted
            if granted <= 0:
                state = "queued"
            elif granted >= demand:
                state = "granted"
            else:
                state = "degraded"
            items.append({
                "asset_id": asset["id"],
                "severity": severity_of.get(asset["id"]),
                "priority": priority.get(asset["id"], 0),
                "demand": demand,
                "granted": granted,
                "state": state,
            })
        return items, capacity

    def _activate_backup(self, actor, link, risen_asset_id=None, risen_priority=None):
        """Create or refresh the active backup allocation for a link."""
        items, capacity = self._compute_backup_items(
            link, risen_asset_id=risen_asset_id, risen_priority=risen_priority
        )
        payload = {
            "link_id": link["id"],
            "station_id": link["data"].get("station_id"),
            "backup_capacity": capacity,
            "allocated": sum(item["granted"] for item in items),
            "items": items,
        }
        existing = self._find_allocation(link["id"])
        if existing:
            updated = self.repository.update_entity(existing["id"], None, "active", payload)
            self.audit.record(
                existing["id"], actor, "activate_backup", existing["status"], "active",
                {"link_id": link["id"]},
            )
            return updated
        entity_id = str(uuid4())
        entity = self.repository.create_entity(
            entity_id, "backup_allocation", "active", payload, actor.user_id
        )
        self.audit.record(entity_id, actor, "activate_backup", None, "active", {"link_id": link["id"]})
        return entity

    def _clear_backup(self, actor, link):
        """Return a link to the regular allocation once the main link is back."""
        existing = self._find_allocation(link["id"])
        if not existing or existing["status"] != "active":
            return existing
        payload = dict(existing["data"])
        payload["items"] = []
        payload["allocated"] = 0
        updated = self.repository.update_entity(existing["id"], None, "normal", payload)
        self.audit.record(
            existing["id"], actor, "restore", "active", "normal", {"link_id": link["id"]}
        )
        return updated

    def _recompute_for_incident(self, actor, incident, risen_asset_id=None, risen_priority=None):
        """Recompute active backup allocations affected by a severity change."""
        station_id = incident["data"].get("station_id")
        link_id = incident["data"].get("link_id")
        for link in self.list("link"):
            if link_id and link["id"] != link_id:
                continue
            if not link_id and station_id and link["data"].get("station_id") != station_id:
                continue
            allocation = self._find_allocation(link["id"])
            if allocation and allocation["status"] == "active":
                self._activate_backup(
                    actor, link, risen_asset_id=risen_asset_id, risen_priority=risen_priority
                )

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
