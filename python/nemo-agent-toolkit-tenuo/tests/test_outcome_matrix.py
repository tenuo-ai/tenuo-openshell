from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "outcome_matrix", ROOT / "examples" / "demo" / "outcome_matrix.py"
)
assert SPEC and SPEC.loader
OUTCOME_MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OUTCOME_MATRIX)


def observations() -> list[dict]:
    rows = []
    for scenario, (protected, control, point, reason) in OUTCOME_MATRIX.EXPECTED.items():
        rows.extend(
            [
                {
                    "scenario": scenario,
                    "run": "openshell+tenuo",
                    "outcome": protected,
                    "point": point,
                    "reason": reason,
                    "verify_us": 7,
                    "e2e_us": 10 if point == "openshell" else 0,
                },
                {
                    "scenario": scenario,
                    "run": "openshell-only",
                    "outcome": control,
                    "point": point,
                    "reason": "",
                    "verify_us": 0,
                    "e2e_us": 8 if point == "openshell" else 0,
                },
            ]
        )
    return rows


def test_expected_observations_are_accepted() -> None:
    checked = OUTCOME_MATRIX.check_pairs(OUTCOME_MATRIX.pair_rows(observations()))
    replay = next(row for row in checked if row["scenario"] == "repeated approved restart")
    assert replay["classification"] == "different"
    assert replay["reason"] == "tenuo_approval_replayed"


def test_duplicate_observation_is_rejected() -> None:
    rows = observations()
    rows.append(rows[0].copy())
    with pytest.raises(SystemExit, match="duplicate observation"):
        OUTCOME_MATRIX.pair_rows(rows)


def test_missing_scenario_is_rejected() -> None:
    paired = OUTCOME_MATRIX.pair_rows(observations())
    paired.pop("missing warrant")
    with pytest.raises(SystemExit, match="missing=.*missing warrant"):
        OUTCOME_MATRIX.check_pairs(paired)


def test_percentile_and_median_e2e() -> None:
    assert OUTCOME_MATRIX.percentile([100, 1, 10], 0.5) == 10
    assert OUTCOME_MATRIX.median_e2e(observations()) == 10
