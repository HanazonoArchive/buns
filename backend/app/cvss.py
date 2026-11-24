"""CVSS v3.1 base score calculator.

The AI proposes a vector; the platform computes the score itself so the
number shown to the assessor is always arithmetically correct and
reproducible, never a value the model made up.
"""

from __future__ import annotations

import math

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    pass


def _roundup(value: float) -> float:
    # Spec-defined round up to one decimal, avoiding float artefacts.
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    v = vector.strip()
    if v.startswith("CVSS:3.1/") or v.startswith("CVSS:3.0/"):
        v = v.split("/", 1)[1]
    metrics: dict[str, str] = {}
    for part in v.split("/"):
        if ":" not in part:
            raise CvssError(f"Malformed metric '{part}'.")
        key, val = part.split(":", 1)
        metrics[key] = val
    missing = [k for k in _REQUIRED if k not in metrics]
    if missing:
        raise CvssError(f"Vector is missing {', '.join(missing)}.")
    if metrics["S"] not in ("U", "C"):
        raise CvssError("Scope must be U or C.")
    for key in ("AV", "AC", "UI", "C", "I", "A"):
        if metrics[key] not in _WEIGHTS[key]:
            raise CvssError(f"Invalid value for {key}: {metrics[key]}.")
    if metrics["PR"] not in _PR["U"]:
        raise CvssError(f"Invalid value for PR: {metrics['PR']}.")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (1 - _WEIGHTS["A"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = (
        8.22
        * _WEIGHTS["AV"][m["AV"]]
        * _WEIGHTS["AC"][m["AC"]]
        * _PR[m["S"]][m["PR"]]
        * _WEIGHTS["UI"][m["UI"]]
    )
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_for(score: float) -> str:
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def normalise(vector: str) -> str:
    m = parse(vector)
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _REQUIRED)
