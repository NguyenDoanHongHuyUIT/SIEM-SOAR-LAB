"""DynamoDB single-table store: cases, audit trail, dedup locks, approval tokens, circuit breaker.

Item layout (pk, sk):
  CASE#<id>   META                  case record (indexed by dedup/resource/status GSIs)
  CASE#<id>   AUDIT#<ts>#<n>        append-only audit entries
  CASE#<id>   TOKEN#<gate>          single-use Step Functions task token (never sent to Slack)
  DEDUP#<key> LOCK                  atomic dedup window lock -> case_id
  ALERT#<id>  SEEN                  idempotency marker for at-least-once EventBridge delivery
  BREAKER#<n> BUCKET#<window>       idempotent isolation counter (string set of case ids)
  RUN#<id>    META                  simulation run + ground truth
"""

from __future__ import annotations

import secrets
from typing import Any

from botocore.exceptions import ClientError

from . import aws
from .states import Status, is_terminal, sources_for
from .util import epoch, from_ddb, iso, to_ddb


class CaseNotFound(KeyError):
    pass


class InvalidTransition(Exception):
    def __init__(self, case_id: str, target: str, current: str | None):
        super().__init__(f"case {case_id}: cannot move to {target} from {current}")
        self.case_id, self.target, self.current = case_id, target, current


class TokenError(Exception):
    pass


class TokenMissing(TokenError):
    pass


class TokenUsed(TokenError):
    pass


def _cond_failed(err: ClientError) -> bool:
    return err.response["Error"]["Code"] == "ConditionalCheckFailedException"


class CaseStore:
    def __init__(self, table_name: str | None = None):
        from .config import settings

        self.name = table_name or settings().table
        self.table = aws.resource("dynamodb").Table(self.name)

    # ---- cases -----------------------------------------------------------------
    def create_case(self, case: dict) -> dict:
        ts = iso()
        item = to_ddb({**case, "pk": f"CASE#{case['case_id']}", "sk": "META", "created_at": ts,
                       "updated_at": ts, "alert_count": case.get("alert_count", 1)})
        self.table.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
        self.audit(case["case_id"], "case_created", "system", {"source": case.get("source"),
                                                              "rule_id": case.get("rule_id")})
        return from_ddb(item)

    def get_case(self, case_id: str) -> dict:
        res = self.table.get_item(Key={"pk": f"CASE#{case_id}", "sk": "META"}, ConsistentRead=True)
        if "Item" not in res:
            raise CaseNotFound(case_id)
        return from_ddb(res["Item"])

    def update_case(self, case_id: str, **attrs: Any) -> None:
        """Set arbitrary attributes on the META item (not status; use transition())."""
        attrs = to_ddb({**attrs, "updated_at": iso()})
        names = {f"#a{i}": k for i, k in enumerate(attrs)}
        values = {f":v{i}": v for i, v in enumerate(attrs.values())}
        expr = "SET " + ", ".join(f"#a{i} = :v{i}" for i in range(len(attrs)))
        self.table.update_item(Key={"pk": f"CASE#{case_id}", "sk": "META"}, UpdateExpression=expr,
                               ExpressionAttributeNames=names, ExpressionAttributeValues=values,
                               ConditionExpression="attribute_exists(pk)")

    def transition(self, case_id: str, target: Status, actor: str = "system",
                   detail: dict | None = None, **attrs: Any) -> dict:
        """Conditional status change; guards against double clicks and out-of-order steps."""
        target = Status(target)
        sources = [s.value for s in sources_for(target)]
        ts = iso()
        attrs = {**attrs, "updated_at": ts, f"{target.value.lower()}_at": ts}
        names = {"#s": "status"}
        values = {":t": target.value}
        sets = ["#s = :t"]
        for i, (k, v) in enumerate(attrs.items()):
            names[f"#a{i}"] = k
            values[f":a{i}"] = to_ddb(v)
            sets.append(f"#a{i} = :a{i}")
        for i, src in enumerate(sources):
            values[f":s{i}"] = src
        cond = "attribute_exists(pk) AND #s IN (" + ",".join(f":s{i}" for i in range(len(sources))) + ")"
        try:
            old = self.table.update_item(
                Key={"pk": f"CASE#{case_id}", "sk": "META"}, UpdateExpression="SET " + ", ".join(sets),
                ConditionExpression=cond, ExpressionAttributeNames=names,
                ExpressionAttributeValues=values, ReturnValues="UPDATED_OLD")
        except ClientError as err:
            if not _cond_failed(err):
                raise
            try:
                current = self.get_case(case_id)["status"]
            except CaseNotFound:
                current = None
            raise InvalidTransition(case_id, target.value, current) from err
        previous = old.get("Attributes", {}).get("status")
        self.audit(case_id, f"status:{target.value}", actor, {"from": previous, **(detail or {})})
        return {"from": previous, "to": target.value, "at": ts}

    def list_cases(self, status: str | None = None, limit: int = 100) -> list[dict]:
        if status:
            res = self.table.query(IndexName="status-index", ScanIndexForward=False, Limit=limit,
                                   KeyConditionExpression="#s = :s", ExpressionAttributeNames={"#s": "status"},
                                   ExpressionAttributeValues={":s": status})
        else:
            res = self.table.scan(FilterExpression="sk = :m", Limit=1000,
                                  ExpressionAttributeValues={":m": "META"})
        return from_ddb(res.get("Items", []))[:limit]

    def cases_for_resource(self, resource_id: str, since: str | None = None) -> list[dict]:
        key = "resource_id = :r" + (" AND created_at > :t" if since else "")
        vals = {":r": resource_id, **({":t": since} if since else {})}
        res = self.table.query(IndexName="resource-index", KeyConditionExpression=key,
                               ExpressionAttributeValues=vals)
        return from_ddb(res.get("Items", []))

    # ---- audit -----------------------------------------------------------------
    def audit(self, case_id: str, action: str, actor: str, detail: dict | None = None) -> None:
        ts = iso()
        self.table.put_item(
            Item=to_ddb({"pk": f"CASE#{case_id}", "sk": f"AUDIT#{ts}#{secrets.token_hex(2)}", "ts": ts,
                         "action": action, "actor": actor, "detail": detail or {}}),
            ConditionExpression="attribute_not_exists(sk)")

    def list_audit(self, case_id: str) -> list[dict]:
        res = self.table.query(KeyConditionExpression="pk = :p AND begins_with(sk, :a)",
                               ExpressionAttributeValues={":p": f"CASE#{case_id}", ":a": "AUDIT#"})
        return from_ddb(res.get("Items", []))

    # ---- dedup & idempotency ------------------------------------------------------
    def first_delivery(self, source_id: str, ttl: int = 86400) -> bool:
        """True the first time an alert id is seen (EventBridge is at-least-once)."""
        try:
            self.table.put_item(Item={"pk": f"ALERT#{source_id}", "sk": "SEEN", "ttl": epoch() + ttl},
                                ConditionExpression="attribute_not_exists(pk)")
            return True
        except ClientError as err:
            if _cond_failed(err):
                return False
            raise

    def acquire_dedup(self, dedup_key: str, case_id: str, window: int) -> str | None:
        """Atomically claim the dedup window. Returns None if acquired, else the existing case id."""
        now = epoch()
        try:
            self.table.put_item(
                Item={"pk": f"DEDUP#{dedup_key}", "sk": "LOCK", "case_id": case_id,
                      "expires_at": now + window, "ttl": now + window + 86400},
                ConditionExpression="attribute_not_exists(pk) OR expires_at < :now",
                ExpressionAttributeValues={":now": now})
            return None
        except ClientError as err:
            if not _cond_failed(err):
                raise
            res = self.table.get_item(Key={"pk": f"DEDUP#{dedup_key}", "sk": "LOCK"}, ConsistentRead=True)
            return res.get("Item", {}).get("case_id")

    def release_dedup(self, dedup_key: str, case_id: str) -> None:
        try:
            self.table.delete_item(Key={"pk": f"DEDUP#{dedup_key}", "sk": "LOCK"},
                                   ConditionExpression="case_id = :c", ExpressionAttributeValues={":c": case_id})
        except ClientError as err:
            if not _cond_failed(err):
                raise

    def bump_alert(self, case_id: str, event_time: str, source_id: str) -> int:
        res = self.table.update_item(
            Key={"pk": f"CASE#{case_id}", "sk": "META"}, UpdateExpression=(
                "ADD alert_count :one SET last_seen = :t, updated_at = :u"),
            ExpressionAttributeValues={":one": 1, ":t": event_time, ":u": iso()},
            ConditionExpression="attribute_exists(pk)", ReturnValues="ALL_NEW")
        count = int(res["Attributes"]["alert_count"])
        self.audit(case_id, "alert_deduplicated", "system", {"source_id": source_id, "alert_count": count})
        return count

    # ---- approval tokens ----------------------------------------------------------
    def save_token(self, case_id: str, gate: str, token: str, ttl: int) -> None:
        self.table.put_item(Item={"pk": f"CASE#{case_id}", "sk": f"TOKEN#{gate}", "task_token": token,
                                  "used": False, "created_at": iso(), "ttl": epoch() + ttl + 86400})

    def consume_token(self, case_id: str, gate: str) -> str:
        """Single-use: flips used False->True atomically. A double click gets TokenUsed."""
        key = {"pk": f"CASE#{case_id}", "sk": f"TOKEN#{gate}"}
        try:
            res = self.table.update_item(
                Key=key, UpdateExpression="SET used = :t, used_at = :u",
                ConditionExpression="attribute_exists(pk) AND used = :f",
                ExpressionAttributeValues={":t": True, ":f": False, ":u": iso()}, ReturnValues="ALL_NEW")
        except ClientError as err:
            if not _cond_failed(err):
                raise
            exists = bool(self.table.get_item(Key=key, ConsistentRead=True).get("Item"))
            raise (TokenUsed if exists else TokenMissing)(f"{case_id}/{gate}") from err
        return res["Attributes"]["task_token"]

    def release_token(self, case_id: str, gate: str) -> None:
        """Undo consume_token when delivering the decision to Step Functions failed transiently."""
        self.table.update_item(Key={"pk": f"CASE#{case_id}", "sk": f"TOKEN#{gate}"},
                               UpdateExpression="SET used = :f", ExpressionAttributeValues={":f": False})

    def has_open_token(self, case_id: str, gate: str) -> bool:
        item = self.table.get_item(Key={"pk": f"CASE#{case_id}", "sk": f"TOKEN#{gate}"}).get("Item")
        return bool(item) and not item.get("used")

    # ---- circuit breaker ----------------------------------------------------------
    def breaker_register(self, case_id: str, limit: int, window: int) -> tuple[int, bool]:
        """Register an isolation attempt. Idempotent per case; returns (count_in_window, tripped)."""
        bucket = epoch() // window
        res = self.table.update_item(
            Key={"pk": "BREAKER#isolation", "sk": f"BUCKET#{bucket}"},
            UpdateExpression="ADD cases :c SET #t = :ttl",
            ExpressionAttributeNames={"#t": "ttl"},
            ExpressionAttributeValues={":c": {case_id}, ":ttl": (bucket + 2) * window},
            ReturnValues="ALL_NEW")
        count = len(res["Attributes"]["cases"])
        return count, count > limit

    # ---- simulation runs ------------------------------------------------------------
    def put_run(self, run: dict) -> None:
        self.table.put_item(Item=to_ddb({**run, "pk": f"RUN#{run['run_id']}", "sk": "META"}))

    def list_runs(self) -> list[dict]:
        res = self.table.scan(FilterExpression="begins_with(pk, :p) AND sk = :m",
                              ExpressionAttributeValues={":p": "RUN#", ":m": "META"})
        return from_ddb(res.get("Items", []))

    def is_terminal_case(self, case_id: str) -> bool:
        return is_terminal(self.get_case(case_id)["status"])
