"""
Matching + scoring for the extraction regression benchmark.

Scoring model (per doc × ontology class):
    tp = # of `required` gold items that at least one predicted entity matched
    fn = # of `required` gold items with no matching prediction
    fp = # of predicted entities that matched NEITHER a required NOR an
         `acceptable` gold item
    (predicted entities that match an `acceptable` item are neutral: they never
     count as fp and never add to tp — this keeps precision fair when the page
     legitimately contains more than we require.)

    precision = tp / (tp + fp)      recall = tp / (tp + fn)      F1 = 2PR/(P+R)

Aggregate metrics are micro-averaged (sum tp/fp/fn, then divide), reported
overall, per-class, and per-doc.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Ontology classes the benchmark scores. Relations are summarized separately.
SCORED_CLASSES = [
    "Vulnerability", "Vendor", "Software", "VulnerabilityType", "Attack", "Impact",
]

# Reported but EXCLUDED from the headline (overall / per-doc) metric. CWE types
# are assigned by the separate validator/mapper stage (semantic CWE mapping),
# not lifted verbatim from the page, so they are a different concern from text
# extraction and would otherwise dominate precision with mapper noise.
INFORMATIONAL_CLASSES = {"VulnerabilityType"}

HEADLINE_CLASSES = [c for c in SCORED_CLASSES if c not in INFORMATIONAL_CLASSES]

_WORD_RE = re.compile(r"[a-z0-9]+")


def _singular(tok: str) -> str:
    """Cheap singularization so 'repositories'~'repository', 'attacks'~'attack'."""
    if len(tok) > 4 and tok.endswith("ies"):
        return tok[:-3] + "y"
    if len(tok) > 3 and tok.endswith("ses"):
        return tok[:-2]
    if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss"):
        return tok[:-1]
    return tok


def norm(s: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace, singularize tokens."""
    return " ".join(_singular(t) for t in _WORD_RE.findall((s or "").lower()))


def _named_match(pred_name: str, item: dict) -> bool:
    """A predicted name matches a gold {name, aliases} item if its normalized
    form equals or is a whole-token superset/subset of any candidate."""
    p = norm(pred_name)
    if not p:
        return False
    cands = [item.get("name", "")] + list(item.get("aliases", []) or [])
    p_tokens = set(p.split())
    for c in cands:
        cn = norm(c)
        if not cn:
            continue
        if p == cn:
            return True
        c_tokens = set(cn.split())
        # subset either direction, but require the shorter to be >=1 token and
        # the overlap to be the entire shorter phrase (avoids 'data' ~ 'data leak'
        # matching everything: shorter must be fully contained as a token set).
        if c_tokens and (c_tokens <= p_tokens or p_tokens <= c_tokens):
            return True
    return False


def _vuln_match(attrs: dict, item: dict) -> bool:
    # ``id_any``: one advisory carrying several equivalent public identifiers
    # (a GitHub advisory page shows both its GHSA and its CVE). Either id
    # identifies the same finding, so requiring one specific spelling would
    # score the pipeline on a coin-flip rather than on whether it found the
    # vulnerability.
    if "id_any" in item:
        got = norm(attrs.get("vuln_id", ""))
        return bool(got) and any(got == norm(i) for i in item["id_any"])
    if "id" in item:
        want = norm(item["id"])
        got = norm(attrs.get("vuln_id", ""))
        return bool(got) and got == want
    if "title_any" in item:
        hay = norm(" ".join(str(attrs.get(k, "")) for k in ("vuln_id", "title", "description")))
        return any(norm(kw) in hay for kw in item["title_any"])
    return False


def _matches(class_name: str, attrs: dict, item: dict) -> bool:
    if class_name == "Vulnerability":
        return _vuln_match(attrs, item)
    name = attrs.get("name") or attrs.get("id") or attrs.get("title") or ""
    return _named_match(name, item)


@dataclass
class ClassScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    matched_required: list = field(default_factory=list)
    missed_required: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)

    @property
    def n_required(self) -> int:
        return self.tp + self.fn

    def precision(self):
        d = self.tp + self.fp
        return (self.tp / d) if d else None

    def recall(self):
        d = self.tp + self.fn
        return (self.tp / d) if d else None

    def f1(self):
        p, r = self.precision(), self.recall()
        if not p or not r:
            return None
        return 2 * p * r / (p + r)


def _label(class_name: str, item: dict) -> str:
    if class_name == "Vulnerability":
        return (
            item.get("id")
            or ("id_any:" + "|".join(item.get("id_any", [])) if item.get("id_any") else None)
            or ("title_any:" + "|".join(item.get("title_any", [])))
        )
    return item.get("name", "?")


def score_class(class_name: str, gold: dict, predicted: list[dict]) -> ClassScore:
    """gold = {required: [...], acceptable: [...]}; predicted = list of attr dicts."""
    required = gold.get("required", []) or []
    acceptable = gold.get("acceptable", []) or []
    sc = ClassScore()

    # Recall: which required items got >=1 prediction.
    for item in required:
        if any(_matches(class_name, p, item) for p in predicted):
            sc.tp += 1
            sc.matched_required.append(_label(class_name, item))
        else:
            sc.fn += 1
            sc.missed_required.append(_label(class_name, item))

    # Precision: predicted that hit neither required nor acceptable are FPs.
    for p in predicted:
        if any(_matches(class_name, p, item) for item in required):
            continue
        if any(_matches(class_name, p, item) for item in acceptable):
            continue
        sc.fp += 1
        sc.false_positives.append(p.get("name") or p.get("vuln_id") or p.get("title") or p)
    return sc


def matches(class_name: str, attrs: dict, item: dict) -> bool:
    """Public: does a predicted entity (attrs) match a single gold item?"""
    return _matches(class_name, attrs, item)


def classify_prediction(class_name: str, attrs: dict, gold: dict) -> str:
    """Verdict for one predicted entity: 'TP' | 'acceptable' | 'FP'."""
    if any(_matches(class_name, attrs, it) for it in (gold.get("required") or [])):
        return "TP"
    if any(_matches(class_name, attrs, it) for it in (gold.get("acceptable") or [])):
        return "acceptable"
    return "FP"


def item_matched(class_name: str, item: dict, predicted: list[dict]) -> bool:
    """True if at least one predicted entity matches this gold item."""
    return any(_matches(class_name, p, item) for p in predicted)


def item_label(class_name: str, item: dict) -> str:
    return _label(class_name, item)


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if (tp + fp) else None
    r = tp / (tp + fn) if (tp + fn) else None
    f = (2 * p * r / (p + r)) if (p and r) else None
    return {"precision": p, "recall": r, "f1": f, "tp": tp, "fp": fp, "fn": fn}
