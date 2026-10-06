import hashlib
import time
from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .rules import RuleEngine

ALLOCATION_ID_PREFIX = "allocation-"

# incidents only reshuffle allocations while the backup channel is in use
BACKUP_LINK_STATUS = "backup_active"
# transitions whose side effect is "the active-incident picture changed"
INCIDENT_REALLOCATE_ACTIONS = ("change_severity", "resolve", "close", "reopen")


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
        self._sync_after_create(actor, entity)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        kind = self.rules.normalize_kind(entity["kind"])
        # a scheduler that submits a switch already in effect sees the current plan
        if kind == "link" and action == "activate_backup" and entity["status"] == BACKUP_LINK_STATUS:
            raise ConflictError(
                "backup link is already active",
                details=self._allocation_details(entity_id, entity["status"]),
            )
        expected = int(expected_version) if expected_version is not None else entity["version"]
        try:
            next_status, patch = self.rules.validate_transition(
                actor, entity, action, dict(data or {}), self._lookup
            )
            merged = dict(entity["data"])
            merged.update(patch)
            updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        except ConflictError as exc:
            if kind == "link" and action == "activate_backup":
                raise ConflictError(
                    "link switch lost the race; the first switch is in effect",
                    details=self._allocation_details(entity_id, wait_for_allocation=True),
                ) from exc
            raise
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        self._sync_after_transition(actor, updated, action)
        return updated

    # ---- backup channel allocation -------------------------------------

    def _allocation_id(self, link_id):
        return ALLOCATION_ID_PREFIX + link_id

    def _get_allocation(self, link_id):
        return self.repository.get_entity(self._allocation_id(link_id))

    def _allocation_details(self, link_id, link_status=None, wait_for_allocation=False):
        """Payload handed to schedulers whose switch did not win."""
        allocation = self._get_allocation(link_id)
        if wait_for_allocation:
            # the winning switch writes the link first, then its allocation;
            # give that write a moment to land so the loser observes the plan
            for _ in range(20):
                if allocation is not None:
                    break
                time.sleep(0.05)
                allocation = self._get_allocation(link_id)
        return {
            "link_id": link_id,
            "link_status": link_status,
            "allocation_id": self._allocation_id(link_id),
            "allocation": allocation,
        }

    def _backup_links(self, station_ids=None, link_ids=None):
        links = [
            link for link in self.repository.list_entities(kind="link")
            if link["status"] == BACKUP_LINK_STATUS
        ]
        if link_ids is not None:
            links = [link for link in links if link["id"] in link_ids]
        if station_ids is not None:
            links = [link for link in links if link["data"].get("station_id") in station_ids]
        return links

    def _affected_links(self, incident):
        """Backup-active links whose asset set an incident can change."""
        data = incident["data"]
        if data.get("link_id"):
            links = self._backup_links(link_ids={data["link_id"]})
        else:
            links = self._backup_links()
        station_ids = set()
        if data.get("station_id"):
            station_ids.add(data["station_id"])
        if data.get("asset_id"):
            asset = self.repository.get_entity(data["asset_id"])
            if asset and asset["data"].get("station_id"):
                station_ids.add(asset["data"]["station_id"])
        if data.get("link_id"):
            return links
        return [link for link in links if link["data"].get("station_id") in station_ids]

    def _apply_backup_plan(self, actor, link, reason):
        assets = self.repository.list_entities(kind="asset")
        incidents = self.repository.list_entities(kind="incident")
        plan = self.rules.build_backup_allocation(link, assets, incidents)
        allocation_id = self._allocation_id(link["id"])
        existing = self.repository.get_entity(allocation_id)
        plan["epoch"] = int(existing["data"].get("epoch", 0)) + 1 if existing else 1
        plan["reason"] = reason
        if existing:
            updated = self.repository.update_entity(
                allocation_id, existing["version"], BACKUP_LINK_STATUS, plan
            )
            self.audit.record(allocation_id, actor, "reallocate_backup", existing["status"],
                             updated["status"], {"reason": reason, "epoch": plan["epoch"]})
            return updated
        created = self.repository.create_entity(
            allocation_id, "allocation", BACKUP_LINK_STATUS, plan, actor.user_id
        )
        self.audit.record(allocation_id, actor, "allocate_backup", None,
                          created["status"], {"reason": reason, "epoch": plan["epoch"]})
        return created

    def _reset_allocation_normal(self, actor, link):
        allocation_id = self._allocation_id(link["id"])
        existing = self.repository.get_entity(allocation_id)
        if not existing:
            return None
        assets = self.repository.list_entities(kind="asset")
        plan = self.rules.build_normal_allocation(link, assets)
        plan["epoch"] = int(existing["data"].get("epoch", 0)) + 1
        plan["reason"] = "link_restored"
        updated = self.repository.update_entity(allocation_id, existing["version"], "normal", plan)
        self.audit.record(allocation_id, actor, "reset_normal", existing["status"], "normal",
                          {"reason": "link_restored", "epoch": plan["epoch"]})
        return updated

    def _sync_after_transition(self, actor, after, action):
        kind = after["kind"]
        if kind == "link":
            if action == "activate_backup":
                self._apply_backup_plan(actor, self.repository.get_entity(after["id"]),
                                        reason="activate_backup")
            elif action == "restore":
                self._reset_allocation_normal(actor, self.repository.get_entity(after["id"]))
        elif kind == "incident" and action in INCIDENT_REALLOCATE_ACTIONS:
            for link in self._affected_links(after):
                self._apply_backup_plan(actor, link, reason="incident_" + action)

    def _sync_after_create(self, actor, entity):
        kind = entity["kind"]
        if kind == "incident":
            for link in self._affected_links(entity):
                self._apply_backup_plan(actor, link, reason="incident_created")
        elif kind == "asset":
            station_id = entity["data"].get("station_id")
            if station_id:
                for link in self._backup_links(station_ids={station_id}):
                    self._apply_backup_plan(actor, link, reason="asset_registered")

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

    def list(self, kind=None, status=None, filters=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        items = self.repository.list_entities(kind=kind, status=status)
        for field, value in (filters or {}).items():
            items = [item for item in items if item["data"].get(field) == value]
        return items

    def allocation_for_link(self, link_id):
        return self._get_allocation(link_id)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
