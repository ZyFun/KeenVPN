"""Вывод только безопасных представлений сохранённого черновика."""

from keenvpn.application.draft_diff import DraftDiffView
from keenvpn.application.draft_session import DraftDiscardOutcome, DraftDiscardView, DraftView
from keenvpn.application.saved_draft import SavedDraftCheckView
from keenvpn.interfaces.cli.presenters import count, created_at, identifier, present_error, safe_text, _check_line


_OPERATIONS = {"added": "добавлено", "removed": "удалено", "changed": "изменено", "reordered": "переставлено"}
_OUTCOMES = {"passed": "успешно", "failed": "ошибка", "incomplete": "неполная"}

NO_SAVED_DRAFT = "Сохранённого черновика нет."


def present_draft_discard_question(view: DraftView) -> tuple[str, ...]:
    """Показать время создания выбранной сессии и запросить явное подтверждение."""
    return (
        f"Удалить черновик, созданный {created_at(view.created_at)}?",
        "  1. Оставить черновик",
        "  2. Удалить черновик",
        "0 или пустая строка — оставить черновик.",
    )


def present_draft_discard(view: DraftDiscardView) -> list[str]:
    """Показать результат отмены без идентификатора сессии."""
    if type(view) is not DraftDiscardView:
        raise TypeError("Ожидается DraftDiscardView.")
    if DraftDiscardOutcome(view.outcome) is DraftDiscardOutcome.DISCARDED:
        return ["Черновик отменён. Настройки не изменились."]
    return [NO_SAVED_DRAFT]


def present_draft_diff(view: DraftDiffView) -> list[str]:
    """Показывать только вид операции, область и порядковые позиции без значений."""
    if type(view) is not DraftDiffView:
        raise TypeError("Ожидается DraftDiffView.")
    if not view.entries:
        return ["Изменений нет: полные снимки совпадают."]
    lines = ["Изменения без секретов:"]
    for item in view.entries:
        position = ""
        if item.part is not None:
            position += f"; часть {count(item.part + 1)}"
        if item.position is not None:
            position += f"; позиция {count(item.position + 1)}"
        lines.append(f"{identifier(item.source.value)} / {identifier(item.area)}: "
                     f"{_OPERATIONS[item.operation.value]}{position}")
    return lines


def present_saved_draft_check(view: SavedDraftCheckView) -> list[str]:
    """Статическая и бинарная проверки имеют отдельные итоги и причины отказа."""
    if type(view) is not SavedDraftCheckView:
        raise TypeError("Ожидается SavedDraftCheckView.")
    lines = ["Статическая проверка:"]
    if view.static_error is not None:
        lines += present_error(view.static_error)
    else:
        lines.append("Итог: " + _OUTCOMES[view.static.outcome])
        lines.extend(_check_line(item) for item in view.static.checks.items)
        if view.static.warnings:
            lines.append("Возможные пересечения правил: " + count(len(view.static.warnings)))
        if view.static.next_step is not None:
            lines.append("Следующий шаг: " + safe_text(view.static.next_step.message))
    lines.append("Бинарная проверка установленным Xray:")
    if view.binary_error is not None:
        lines += present_error(view.binary_error)
    else:
        lines.append(_check_line(view.binary))
    return lines
