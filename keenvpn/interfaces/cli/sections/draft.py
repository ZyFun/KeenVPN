"""Просмотр, проверка и отмена черновика, выход из меню."""

import re

from keenvpn.application.contract import OperationIdFactory, Result
from keenvpn.application.draft_diff import DraftDiffView
from keenvpn.application.draft_session import (
    DiscardDraft, DiscardDraftHandler, DraftDiscardOutcome, DraftDiscardView, DraftView, InspectDraft,
    InspectDraftHandler,
)
from keenvpn.application.menu_exit import (
    InspectMenuExit, InspectMenuExitHandler, MenuExitDecision, MenuExitReason, MenuExitView,
)
from keenvpn.application.saved_draft import (
    CheckSavedDraft, CheckSavedDraftHandler, CompareSavedDraft, CompareSavedDraftHandler, SavedDraftCheckView,
)
from keenvpn.interfaces.cli.bindings import MenuSources, SectionActions
from keenvpn.interfaces.cli.menu import ConfirmationRequest, ExitNotice, UnavailableReason
from keenvpn.interfaces.cli.presentation import (
    check_line, count, HIDDEN, identifier, present_error, present_result, safe_text,
)
from keenvpn.interfaces.cli.terminal import ExitCheck

ACTION_CAPTIONS = {
    "draft.diff": "Сравнение сохранённого черновика с исходной ревизией. Значения замаскированы.",
    "draft.check": "Проверка сохранённого черновика. Запуск Xray зависит от кандидата и условий проверки.",
    "draft.save_and_exit": "Выход с проверкой сохранённого черновика.",
}


_CREATED_AT = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})Z")
"""Момент создания сессии в UTC."""

DRAFT_NOT_CONNECTED = "Черновик не проверялся: хранилище черновика не подключено."

DRAFT_NOT_CHECKED = "Не удалось проверить, есть ли неприменённый черновик."

DRAFT_KEPT = "При выходе он сохранится без изменений; настройки роутера не меняются."

DRAFT_KEPT_IF_PRESENT = "Если он есть, при выходе он сохранится без изменений; настройки роутера не меняются."


def created_at(value: object) -> str:
    """Время создания черновика `YYYY-MM-DDTHH:MM:SSZ` в виде `YYYY-MM-DD HH:MM:SS UTC`; иное — пометка."""
    match = _CREATED_AT.fullmatch(value) if type(value) is str else None
    return HIDDEN if match is None else f"{match[1]} {match[2]} UTC"


def present_menu_exit(result: Result) -> ExitNotice:
    """Строки и признак вопроса при выходе по решению сценария выхода.

    Вопрос задаётся, если его требует решение сценария; причина выбирает
    заранее заданные строки. Отказ сценария показывается как отказ чтения:
    вопрос задаётся, а не выход, будто черновика нет. Идентификатор
    и токен черновика сценарий не возвращает, путей в строках нет.
    """
    if type(result) is not Result:
        raise TypeError("Ожидается Result сценария.")
    if not result.succeeded:
        return ExitNotice((DRAFT_NOT_CHECKED, *present_error(result.error), DRAFT_KEPT_IF_PRESENT), True)
    view = result.data
    if type(view) is not MenuExitView:
        raise TypeError("Ожидается MenuExitView.")
    confirm = view.decision is MenuExitDecision.CONFIRM
    if view.reason is MenuExitReason.DRAFT_PRESENT:
        lines = (f"Черновик изменений создан {created_at(view.draft_created_at)} и не применён.", DRAFT_KEPT)
    elif view.reason is MenuExitReason.DRAFT_NOT_CHECKED:
        lines = (DRAFT_NOT_CHECKED, *present_error(view.store_error), DRAFT_KEPT_IF_PRESENT)
    elif view.reason is MenuExitReason.DRAFT_STORE_NOT_CONNECTED:
        lines = (DRAFT_NOT_CONNECTED,)
    else:
        lines = ()
    return ExitNotice(lines, confirm)

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
        lines.extend(check_line(item) for item in view.static.checks.items)
        if view.static.warnings:
            lines.append("Возможные пересечения правил: " + count(len(view.static.warnings)))
        if view.static.next_step is not None:
            lines.append("Следующий шаг: " + safe_text(view.static.next_step.message))
    lines.append("Бинарная проверка установленным Xray:")
    if view.binary_error is not None:
        lines += present_error(view.binary_error)
    else:
        lines.append(check_line(view.binary))
    return lines


def bind_actions(
    bindings: SectionActions, sources: MenuSources, operation_ids: OperationIdFactory, storage_notice: list[str],
) -> ExitCheck:
    """Подключить доступные операции с черновиком и общую проверку выхода."""
    drafts = sources.draft_store
    bindings["draft.discard"] = (UnavailableReason.DRAFT_STORE_NOT_CONNECTED if drafts is None
                                 else UnavailableReason.DRAFT_DISCARD_NOT_CONNECTED)
    if sources.storage_error is not None:
        bindings["draft.diff"] = UnavailableReason.STORAGE_NOT_CONFIRMED
        bindings["draft.check"] = UnavailableReason.STORAGE_NOT_CONFIRMED
        if drafts is None:
            bindings["draft.discard"] = UnavailableReason.STORAGE_NOT_CONFIRMED

    menu_exit = InspectMenuExitHandler(drafts, operation_ids=operation_ids)

    def exit_check() -> ExitNotice:
        notice = present_menu_exit(menu_exit.execute(InspectMenuExit()))
        return ExitNotice((*notice.lines, *storage_notice), notice.confirm)

    bindings["draft.save_and_exit"] = exit_check
    if sources.draft_discard is not None:
        inspect_for_discard = InspectDraftHandler(sources.draft_discard, operation_ids=operation_ids)
        discard = DiscardDraftHandler(sources.draft_discard, operation_ids=operation_ids)

        def discard_action() -> list[str] | ConfirmationRequest:
            inspected = inspect_for_discard.execute(InspectDraft())
            if not inspected.succeeded:
                return present_error(inspected.error)
            view = inspected.data.draft
            if view is None:
                return [NO_SAVED_DRAFT]
            # Команда относится к выбранной сессии, показанной до подтверждения.
            command = DiscardDraft(draft_id=view.draft_id, expected_revision=view.revision)
            return ConfirmationRequest(
                present_draft_discard_question(view),
                lambda: present_result(discard.execute(command), present_draft_discard),
            )

        bindings["draft.discard"] = discard_action

    if drafts is not None and sources.fingerprints is not None:
        inspect_draft = InspectDraftHandler(drafts, operation_ids=operation_ids)
        compare = CompareSavedDraftHandler(drafts, sources.fingerprints, operation_ids=operation_ids)
        check = CheckSavedDraftHandler(drafts, sources.fingerprints, sources.geodata,
            sources.candidate_assets, sources.geo_catalogs, sources.installed_xray, operation_ids=operation_ids)

        def saved_action(handler, command_type, presenter):
            def action():
                inspected = inspect_draft.execute(InspectDraft())
                if not inspected.succeeded:
                    return present_result(inspected, presenter)
                view = inspected.data.draft
                if view is None:
                    return [NO_SAVED_DRAFT]
                # ID и токен остаются в состоянии вызова и не выводятся.
                return present_result(handler.execute(command_type(draft_id=view.draft_id,
                    expected_revision=view.revision)), presenter)
            return action


        bindings["draft.diff"] = saved_action(compare, CompareSavedDraft, present_draft_diff)
        bindings["draft.check"] = saved_action(check, CheckSavedDraft, present_saved_draft_check)
    return exit_check
