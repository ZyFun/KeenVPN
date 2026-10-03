"""Доменные модели из обезличенного снимка только для локальных тестов.

Это проекция фикстур `tests/fixtures/router_snapshot`, а не адаптер RCI:
чтение роутера, разрешённые подключения политик и остальные поля сюда
не переносятся. Снимок обезличен; реальные данные здесь не появляются.
"""

import json
from pathlib import Path

from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet


SNAPSHOT_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "router_snapshot"


def load_keenetic_snapshot() -> dict[str, object]:
    """Прочитать обезличенные ответы RCI из фикстуры."""
    return json.loads((SNAPSHOT_ROOT / "keenetic.json").read_text(encoding="utf-8"))


def policies_from_rci(payload: dict[str, dict[str, object]]) -> KeeneticPolicySet:
    """Собрать модели из объекта `ip/policy`: ключ — ID, `description` — метка.

    Порядок ключей сохраняется. Отсутствующее описание остаётся None,
    пустая строка не подставляется.
    """
    return KeeneticPolicySet(tuple(
        KeeneticPolicy(policy_id, entry.get("description")) for policy_id, entry in payload.items()
    ))


def snapshot_policies() -> KeeneticPolicySet:
    """Политики обезличенного снимка в порядке фикстуры."""
    return policies_from_rci(load_keenetic_snapshot()["ip/policy"])
