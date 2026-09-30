from __future__ import annotations

from dataclasses import dataclass

from fabweave.core.decision import Decision, allow, deny
from fabweave.core.ids import validate_id
from fabweave.core.timebox import TimeBox


NORMAL = "NORMAL"
HOT = "HOT"
ENGINEERING = "ENGINEERING"
LOT_CLASSES = frozenset({NORMAL, HOT, ENGINEERING})

FREEZE = "FREEZE"
OVERRIDE = "OVERRIDE"
_RULE_KINDS = frozenset({FREEZE, OVERRIDE})


@dataclass(frozen=True, slots=True)
class FreezeRule:
    """One versioned dispatch-freeze rule scoped to lot classes over a half-open window.

    OVERRIDE rules are time-limited authorizations: they govern only inside
    their window, so an expired override lapses without any cleanup.
    """

    rule_id: str
    version: int
    kind: str
    scope: frozenset[str]
    window: TimeBox
    priority: int = 0
    effective_at: int = 0
    granted_by: str | None = None

    def __post_init__(self) -> None:
        validate_id(self.rule_id)
        if self.version <= 0:
            raise ValueError("rule version must be positive")
        if self.kind not in _RULE_KINDS:
            raise ValueError("unknown rule kind")
        scope = frozenset(self.scope)
        if not scope or not scope <= LOT_CLASSES:
            raise ValueError("scope must name known lot classes")
        object.__setattr__(self, "scope", scope)
        if self.kind == OVERRIDE and not self.granted_by:
            raise ValueError("overrides require a grantor")
        if self.kind == FREEZE and self.granted_by is not None:
            raise ValueError("only overrides record a grantor")


def _precedence(rule: FreezeRule) -> tuple[int, int, int, str]:
    # Overlaps resolve by priority, then version, then effective time; the
    # rule id only breaks exact ties so the outcome stays deterministic.
    return (rule.priority, rule.version, rule.effective_at, rule.rule_id)


def _current_revisions(rules: list[FreezeRule], at: int) -> list[FreezeRule]:
    current: dict[str, FreezeRule] = {}
    for rule in rules:
        if rule.effective_at > at:
            continue
        previous = current.get(rule.rule_id)
        if previous is None or (rule.version, rule.effective_at) > (previous.version, previous.effective_at):
            current[rule.rule_id] = rule
    return list(current.values())


def _contenders(rules: list[FreezeRule], lot_class: str, at: int) -> tuple[FreezeRule, ...]:
    if lot_class not in LOT_CLASSES:
        raise ValueError("unknown lot class")
    matched = (
        rule
        for rule in _current_revisions(rules, at)
        if lot_class in rule.scope and rule.window.contains(at)
    )
    return tuple(sorted(matched, key=_precedence, reverse=True))


@dataclass(frozen=True, slots=True)
class FreezeExplanation:
    """A decision plus the rule contest that produced it, for any instant."""

    lot_class: str
    evaluated_at: int
    decision: Decision
    winner: FreezeRule | None
    contenders: tuple[FreezeRule, ...]


def explain_freeze(rules: list[FreezeRule], lot_class: str, at: int) -> FreezeExplanation:
    contenders = _contenders(rules, lot_class, at)
    winner = contenders[0] if contenders else None
    evidence: dict[str, object] = {
        "lot_class": lot_class,
        "evaluated_at": at,
        "contenders": tuple((rule.rule_id, rule.kind, rule.version, rule.priority) for rule in contenders),
    }
    if winner is not None:
        evidence.update(
            winning_rule_id=winner.rule_id,
            winning_kind=winner.kind,
            winning_version=winner.version,
            winning_priority=winner.priority,
            window_start=winner.window.start,
            window_end=winner.window.end,
        )
    if winner is None:
        decision = allow(**evidence)
    elif winner.kind == OVERRIDE:
        decision = allow(**evidence, granted_by=winner.granted_by, override_expires_at=winner.window.end)
    else:
        decision = deny("dispatch_frozen", **evidence)
    return FreezeExplanation(lot_class, at, decision, winner, contenders)


def freeze_decision(rules: list[FreezeRule], lot_class: str, at: int) -> Decision:
    return explain_freeze(rules, lot_class, at).decision


class FreezeRegistry:
    """Append-only rule book: versions supersede per rule id and never mutate."""

    def __init__(self) -> None:
        self._history: dict[str, list[FreezeRule]] = {}

    def publish(self, rule: FreezeRule) -> FreezeRule:
        history = self._history.setdefault(rule.rule_id, [])
        if history:
            last = history[-1]
            if rule.version <= last.version or rule.effective_at < last.effective_at:
                raise ValueError("rule revisions must move forward")
        history.append(rule)
        return rule

    def rules(self, rule_id: str) -> tuple[FreezeRule, ...]:
        return tuple(self._history.get(rule_id, ()))

    def decision(self, lot_class: str, at: int) -> Decision:
        return freeze_decision(self._published(), lot_class, at)

    def explain(self, lot_class: str, at: int) -> FreezeExplanation:
        return explain_freeze(self._published(), lot_class, at)

    def _published(self) -> list[FreezeRule]:
        return [rule for history in self._history.values() for rule in history]
