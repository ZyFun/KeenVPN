"""Список, карточки и объяснение правил маршрутизации."""

import re
from collections.abc import Mapping
from types import MappingProxyType

from keenvpn.application.contract import OperationIdFactory
from keenvpn.application.ports import GeoDataSource, ManagerMetadataStore
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing import (
    ExplainRoute, ExplainRouteHandler, OUTCOME_LABELS, RouteExplanationView, RouteOutcome, RouteSelectionView,
    RouteStepView, STEP_RESULT_LABELS, STEP_SKIPPED_LABEL,
)
from keenvpn.application.routing_import import ImportRoutingSchemeHandler, RoutingSchemeView, RuleGroupView
from keenvpn.application.routing_rules import (
    ListRoutingRules, ListRoutingRulesHandler, MetadataState, RuleGroupIdentityView, RuleListEntryView,
    RuleListView, TargetPositionState,
)
from keenvpn.interfaces.cli.bindings import SectionActions
from keenvpn.interfaces.cli.menu import ListEntry, MAX_ITEM_NUMBER, MenuList, ValueRequest
from keenvpn.interfaces.cli.presentation import (
    catalog_label, INDENT, indented, report_paragraphs, xray_position, checked_text, user_text, count, file_name, flag, HIDDEN,
    identifier, identifiers, known_value, Lines, MISSING, optional_count, optional_file_name, present_error,
    present_result, ReportLayout, safe_text,
)

ACTION_CAPTIONS = {
    "routing.list": "Группы правил Xray в порядке конфигурации. Названия и ID зависят от метаданных.",
    "routing.explain": "Предварительный расчёт по импортированной схеме без DNS-запросов и отправки трафика.",
}


_RULE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

MAX_RULE_NAME_LENGTH = 64
"""Предел названия правила в символах: тот же, что у модели маршрутизации."""


def rule_id(value: object) -> str:
    """Показать идентификатор правила только в канонической форме UUID; иначе пометку."""
    return checked_text(_RULE_ID, value)


def rule_name(value: object) -> str:
    """Показать название правила — пользовательский текст — по общему правилу пользовательского текста."""
    return user_text(value, MAX_RULE_NAME_LENGTH)

ROUTING_LIST_TITLE = "Группы правил"

ROUTING_ITEM_NAME = "Группа правил"

OUTBOUND_TAGS_PER_LINE = 10
"""Сколько тегов outbound в строке карточки: тег после фильтра не длиннее 64 символов, строка остаётся в пределе."""

API_SERVICE_NOTE = "служебное правило API — в политику не входит"
"""Подпись группы, которая направляет трафик служебного inbound в обработчик API Xray."""


def _value_reasons(group: RuleGroupView) -> str:
    # Пути значений не выводятся: они ведут к условиям, а для диагностики достаточно кодов.
    counts: dict[str, int] = {}
    for item in group.value_reasons:
        code = identifier(item.reason)
        counts[code] = counts.get(code, 0) + 1
    return ", ".join(f"{code} ×{number}" for code, number in counts.items())


def _condition_types(group: RuleGroupView) -> str:
    return ", ".join(f"{identifier(item.name)} {count(item.count)}" for item in group.condition_types) or "нет"


def _group_label(group: RuleGroupView) -> str:
    target = group.target
    line = (
        f"{identifier(group.kind)}: условий {count(group.condition_count)} ({_condition_types(group)}), "
        f"значений {count(group.value_count)}, действие "
        f"{'нет' if group.action is None else identifier(group.action)}, назначение "
        f"{identifier(target.kind)} {known_value(target.tag_known, target.tag, identifier, 'без тега')}, "
        f"только просмотр {flag(group.read_only)}"
    )
    if group.api_service is True:
        line += f", {API_SERVICE_NOTE}"
    if group.reasons:
        line += f", причины: {identifiers(group.reasons)}"
    if target.reasons:
        line += f", причины назначения: {identifiers(target.reasons)}"
    if group.value_reasons:
        line += f", причины значений: {_value_reasons(group)}"
    if group.unknown_field_count:
        line += f", неизвестных полей {count(group.unknown_field_count)}"
    return line


def _rule_tag(has_rule_tag: object) -> str:
    if has_rule_tag is True:
        return "задан, значение не показывается"
    return "не задан" if has_rule_tag is False else HIDDEN


def _outbound_lines(tags: tuple[object, ...]) -> list[str]:
    # Число outbound задаёт конфигурация, поэтому теги идут строками по OUTBOUND_TAGS_PER_LINE.
    lines = [f"Outbound назначения: {count(len(tags))}"]
    for start in range(0, len(tags), OUTBOUND_TAGS_PER_LINE):
        lines.append(INDENT + identifiers(tags[start:start + OUTBOUND_TAGS_PER_LINE]))
    return lines


def _group_card(group: RuleGroupView) -> tuple[str, ...]:
    target = group.target
    return (
        f"Часть: {file_name(group.part)}; индекс правила Xray: {count(group.index)} (счёт с нуля)",
        f"Вид: {identifier(group.kind)}; только просмотр: {flag(group.read_only)}; "
        f"причины: {identifiers(group.reasons)}",
        f"Условий: {count(group.condition_count)} ({_condition_types(group)}); значений: {count(group.value_count)}; "
        "сами значения не показываются",
        f"Причины значений: {_value_reasons(group) or 'нет'}",
        f"Поля правила: {identifiers(group.fields)}; неподдержанные: {identifiers(group.unsupported_fields)}; "
        f"неизвестных: {count(group.unknown_field_count)}",
        f"Тег правила: {_rule_tag(group.has_rule_tag)}",
        f"Действие: {'нет' if group.action is None else identifier(group.action)}",
        f"Служебное правило API: {API_SERVICE_NOTE if group.api_service is True else flag(group.api_service)}",
        f"Назначение: {identifier(target.kind)} {known_value(target.tag_known, target.tag, identifier, 'без тега')}; "
        f"запасной: {known_value(target.fallback_known, target.fallback_tag, identifier, 'не задан')}; "
        f"стратегия: {known_value(target.strategy_known, target.strategy, identifier, 'не задана')}; "
        f"действие назначения: {'нет' if target.action is None else identifier(target.action)}",
        *_outbound_lines(target.outbound_tags),
        f"Причины назначения: {identifiers(target.reasons)}",
    )


def present_routing_scheme(view: RoutingSchemeView) -> MenuList:
    """Показать импортированные группы правил списком без доменов, адресов и кодов наборов.

    Номер группы — её позиция в схеме, начиная с 1: он не меняется при поиске.
    Строка списка и карточка собираются из тех же отфильтрованных значений.
    """
    if type(view) is not RoutingSchemeView:
        raise TypeError("Ожидается RoutingSchemeView.")
    header = [
        "Правила маршрутизации по конфигурации Xray",
        f"Часть с маршрутизацией: {optional_file_name(view.routing_part)}; частей с разделом routing: "
        f"{count(len(view.routing_parts))}",
        f"Групп правил: {count(view.group_count)}; правил модели: {count(view.rule_count)}; "
        f"финальное действие: {'не определено' if view.final_action is None else identifier(view.final_action)}",
        f"Только для просмотра: {flag(view.read_only)}; причины: {identifiers(view.reasons)}",
    ]
    policy = view.policy
    if policy is None:
        header.append("Политика маршрутизации не собрана: схема доступна только для просмотра.")
    else:
        header.append(
            f"Политика: правил {count(policy.rule_count)}, включено {count(policy.active_rule_count)}, "
            f"служебных {count(policy.protected_rule_count)}, финальное действие {identifier(policy.final_action)}, "
            f"только просмотр {flag(policy.read_only)}"
        )
    groups = view.groups[:MAX_ITEM_NUMBER]
    if len(view.groups) > MAX_ITEM_NUMBER:
        header.append(f"Групп больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.")
    entries = tuple(
        ListEntry(number, _group_label(group), _group_card(group)) for number, group in enumerate(groups, start=1)
    )
    return MenuList(ROUTING_LIST_TITLE, ROUTING_ITEM_NAME, tuple(header), entries)

NAMES_PER_LABEL = 10
"""Сколько названий правил входит в строку группы: название не длиннее 64 символов, строка остаётся в пределе."""

METADATA_NOTES: Mapping[MetadataState, str] = MappingProxyType({
    MetadataState.NOT_CONNECTED: "Хранилище метаданных не подключено: названия и идентификаторы правил не показываются.",
    MetadataState.ABSENT: "Метаданные менеджера не записаны: идентификаторы правилам ещё не присвоены.",
    MetadataState.PRESENT: "Метаданные менеджера прочитаны.",
    MetadataState.FAILED: "Названия и идентификаторы недоступны: хранилище метаданных отказало, список показан без них.",
})
"""Строка состояния метаданных в списке правил. Таблица только для чтения."""

TARGET_POSITION_LABELS: Mapping[TargetPositionState, str] = MappingProxyType({
    TargetPositionState.AMBIGUOUS: "не определена однозначно: тег повторяется",
    TargetPositionState.UNRESOLVED: "не найдена: тега нет ни в одной части",
    TargetPositionState.ABSENT: "без тега",
    TargetPositionState.UNSUPPORTED: "не определена: заданы оба тега",
    TargetPositionState.UNAVAILABLE: "сводка не описывает это правило",
    TargetPositionState.API: "обработчик API Xray, служебное назначение",
})
"""Подпись позиции назначения группы, когда позиция не разрешена. Таблица только для чтения."""


def _target_position(group: RuleGroupIdentityView) -> str:
    state = group.target_position_state
    if type(state) is not TargetPositionState:
        return HIDDEN
    if state is TargetPositionState.RESOLVED:
        return xray_position(group.target_position)
    return safe_text(TARGET_POSITION_LABELS[state])


def _rule_name_text(item: RuleListEntryView) -> str:
    return f"«{rule_name(item.name)}»" if item.has_name is True else "не задано"


def _identity_label(group: RuleGroupIdentityView) -> str:
    line = f", правил {count(group.rule_count)}"
    rules = group.rules
    if rules is None:
        return line
    with_id = sum(item.has_id is True for item in rules)
    names = [item for item in rules if item.has_name is True]
    line += f", с ID {count(with_id)}, с названием {count(len(names))}"
    if names:
        shown = ", ".join(_rule_name_text(item) for item in names[:NAMES_PER_LABEL])
        line += f", названия: {shown}"
        if len(names) > NAMES_PER_LABEL:
            line += f" (ещё {count(len(names) - NAMES_PER_LABEL)})"
    return line


def _rule_line(item: RuleListEntryView) -> str:
    return (
        f"{count(item.index)}: {identifier(item.condition_type)}, действие {identifier(item.action)}, "
        f"только просмотр {flag(item.read_only)}, ID {rule_id(item.rule_id) if item.has_id is True else 'не присвоен'}, "
        f"название {_rule_name_text(item)}, привязка {identifier(item.binding)}"
    )


def _identity_card(group: RuleGroupIdentityView) -> list[str]:
    lines = [f"Назначение по позиции: {_target_position(group)}"]
    if group.rules is None:
        lines.append(f"Правил модели: {count(group.rule_count)}; названия и идентификаторы недоступны")
        return lines
    lines.append(f"Правил модели: {count(group.rule_count)} (позиция в схеме, счёт с нуля)")
    lines.extend(INDENT + _rule_line(item) for item in group.rules)
    return lines


def _metadata_state_lines(state: object, error: object) -> Lines:
    """Строка состояния метаданных и, при отказе хранилища, строки отказа с его шагом."""
    if type(state) is not MetadataState:
        return [HIDDEN]
    lines = [safe_text(METADATA_NOTES[state])]
    if error is not None:
        lines += indented(present_error(error))
    return lines


def _metadata_lines(view: RuleListView) -> Lines:
    lines = _metadata_state_lines(view.metadata_state, view.metadata_error)
    identity = view.identity
    if identity is not None:
        records = "раздел записей не записан" if identity.record_count is None else f"записей правил {count(identity.record_count)}"
        lines.append(
            f"Идентичность: {records}; привязано {count(identity.bound_rule_count)}, "
            f"с названием {count(identity.named_rule_count)}, без привязки {count(identity.unbound_rule_count)}; "
            f"записей без правила {count(identity.unbound_record_count)}"
        )
    return lines

_CONDITION_NAMES = {
    "DomainCondition": "Домены", "IPCondition": "IP и подсети", "GeoIPCondition": "GeoIP",
    "GeoSiteCondition": "GeoSite", "UnknownCondition": "Нераспознанные значения",
    "UnsupportedRuleCondition": "Условие Xray",
}

_TARGET_NAMES = {"outbound": "выход", "balancer": "балансировщик", "api": "обработчик API"}

_ROUTE_ACTIONS = ("DIRECT", "VPN", "BLOCK")


def _brief_target(group: RuleGroupView, position: TargetPositionState, tag: str) -> str:
    """Различать указанный тег и подтверждённое назначение конфигурации."""
    if position is TargetPositionState.UNSUPPORTED:
        return "конфликт outboundTag и balancerTag"
    if position is TargetPositionState.UNAVAILABLE:
        return "сведения о назначении недоступны"
    if "target_invalid" in group.target.reasons:
        return "некорректный тег назначения"
    if "field_case_variant" in group.target.reasons and group.target.kind == "none":
        return "регистр поля назначения не поддерживается"
    if position is TargetPositionState.ABSENT:
        return "тег назначения не задан"
    if position is TargetPositionState.AMBIGUOUS:
        return f"тег {tag} повторяется"
    named = f"{_TARGET_NAMES.get(group.target.kind, 'тег')} {tag}"
    if position is TargetPositionState.UNRESOLVED:
        return f"{named} не найден"
    return named


def _rule_entry(entry: ListEntry, group: RuleGroupView, identity: RuleGroupIdentityView) -> ListEntry:
    """Собрать краткий обзор только из безопасных полей группы и реально назначенных имён."""
    if group.api_service is True:
        subject = "Служебное API"
    elif group.kind == "final":
        subject = "Остальной трафик"
    elif group.fields == ("inboundTag",) and group.unsupported_fields == ("inboundTag",):
        subject = "Входящий тег Xray"
    else:
        types = [_CONDITION_NAMES.get(item.name, "Условие Xray") for item in group.condition_types]
        subject = ", ".join(dict.fromkeys(types)) or "Группа условий"

    tag = known_value(group.target.tag_known, group.target.tag, identifier, "без тега")
    target = _brief_target(group, identity.target_position_state, tag)
    action = group.action if group.action in _ROUTE_ACTIONS else "не определено"
    if group.api_service is True:
        destination = tag
    elif group.action in _ROUTE_ACTIONS:
        destination = action
        if group.target.tag_known and tag != HIDDEN and tag.casefold() != action.casefold():
            destination += f" · {tag}"
    else:
        destination = target

    brief = f"{subject} → {destination}"
    preview = [subject, f"Назначение: {target}"]
    if group.api_service is True:
        preview.append("Служебный трафик API Xray. В политику маршрутизации не входит.")
    else:
        preview.extend((f"Действие: {action}", f"Условий: {count(group.condition_count)} · "
                        f"Значений: {count(group.value_count)} · Правил модели: {count(identity.rule_count)}"))
    if group.read_only is True:
        preview.append("Только для просмотра.")
    if group.unsupported_fields:
        preview.append("KeenVPN не поддерживает поля условий: " + identifiers(group.unsupported_fields))
    if "outbound_protocol_unsupported" in group.target.reasons:
        preview.append("KeenVPN не определил действие для протокола выхода.")
    if "fallback_mixed" in group.target.reasons:
        preview.append("Запасной выход и выходы балансировщика задают разные действия.")
    if identity.rules:
        names = [item for item in identity.rules if item.has_name]
        if len(identity.rules) == 1 and names:
            name = _rule_name_text(names[0])
            brief = f"{name} · {brief}"
            preview.insert(0, name)
        elif names:
            preview.append("Названия правил: " + ", ".join(_rule_name_text(item) for item in names[:NAMES_PER_LABEL]))
    return ListEntry(entry.number, entry.label + _identity_label(identity), (*entry.card, *_identity_card(identity)),
                     brief=brief, preview=tuple(preview))


def present_rule_list(view: RuleListView) -> MenuList:
    """Показать группы правил в фактическом порядке с названиями и идентификаторами, когда они доступны.

    Список, строки и карточки групп те же, что у представления схемы; к строке
    добавляются число правил, счётчики идентичности и до `NAMES_PER_LABEL`
    названий, к карточке — позиция назначения и по строке на правило модели.
    Названия проходят фильтр `rule_name`, идентификаторы — `rule_id`.
    """
    if type(view) is not RuleListView:
        raise TypeError("Ожидается RuleListView.")
    base = present_routing_scheme(view.scheme)
    header = (*base.header, *_metadata_lines(view))
    scheme = view.scheme
    summary = [f"Групп: {count(scheme.group_count)} · Правил модели: {count(scheme.rule_count)}"]
    final = scheme.final_action if scheme.final_action in _ROUTE_ACTIONS else "не определено"
    summary.append(f"Финальное действие: {final}" + (" · Только просмотр" if scheme.read_only is True else ""))
    if scheme.policy is None:
        summary.append("Политика маршрутизации не собрана.")
    if view.metadata_state in (MetadataState.FAILED, MetadataState.NOT_CONNECTED):
        summary.append("Имена и ID недоступны: хранилище " +
                       ("не прочитано." if view.metadata_state is MetadataState.FAILED else "не подключено."))
    if len(view.groups) > MAX_ITEM_NUMBER:
        summary.append(f"Показаны первые {MAX_ITEM_NUMBER} групп.")
    entries = tuple(_rule_entry(entry, group, identity) for entry, group, identity in zip(
        base.entries, scheme.groups[:MAX_ITEM_NUMBER], view.groups[:MAX_ITEM_NUMBER], strict=True,
    ))
    return MenuList(base.title, base.item_name, header, entries, summary=tuple(summary), split_preview=False)

ROUTE_PROMPT = (
    "Домен, отдельный IP-адрес или домен с IP-адресами через пробел: не больше одного домена и 16 адресов, "
    "без CIDR, портов и зон.",
    "Введённое значение в вывод не повторяется; DNS и другие сетевые запросы не выполняются.",
)
"""Подсказка запроса значения для объяснения маршрута."""

ROUTE_NOTE = (
    "Это предварительный статический расчёт по снимку импортированных правил: реальный путь трафика, DNS, "
    "sniffing и работа VPN не проверялись, введённые значения не выводятся."
)

UNKNOWN_ROUTE_NOTE = "Маршрут не определён: это не DIRECT, не VPN и не BLOCK."

POLICY_ABSENT_NOTE = (
    "Правила не проверялись: политика действующей схемы не собрана, схема доступна только для просмотра; "
    "причины — в строке схемы."
)


def _route_position(index: object, group_index: object, offset: object) -> str:
    text = f"правило {count(index)}"
    if group_index is None:
        return text
    inside = "" if offset is None else f", правило {count(offset)} в группе"
    return f"{text} (группа {count(group_index)}{inside})"


def _route_identity(has_id: object, rule_id_value: object, has_name: object, name: object) -> str:
    shown_id = rule_id(rule_id_value) if has_id is True else "не присвоен"
    shown_name = f"«{rule_name(name)}»" if has_name is True else "не задано"
    return f"ID {shown_id}; название {shown_name}"


def _route_step_line(number: int, step: RouteStepView) -> str:
    result = STEP_SKIPPED_LABEL if step.result is None else catalog_label(STEP_RESULT_LABELS, step.result)
    condition = "финальное правило" if step.condition_type is None else identifier(step.condition_type)
    line = (
        f"Шаг {count(number)}: {_route_position(step.index, step.group_index, step.offset)} — {condition}, "
        f"действие {identifier(step.action)}, {safe_text(result)}; {safe_text(step.reason)}"
    )
    if step.condition_type is not None:
        line += f"; {_route_identity(step.has_id, step.rule_id, step.has_name, step.name)}"
    if step.database_kind is not None:
        version = "известна" if step.database_version_known is True else "неизвестна"
        line += f"; база {identifier(step.database_kind)}, версия {version}"
    return line


def _route_target_line(selection: RouteSelectionView) -> str:
    target = selection.target
    if target is None:
        return f"Назначение: {MISSING}"
    state = selection.target_position_state
    if type(state) is not TargetPositionState:
        position = HIDDEN
    elif state is TargetPositionState.RESOLVED:
        position = f"{file_name(selection.target_position.part)}, индекс {count(selection.target_position.index)}"
    else:
        position = safe_text(TARGET_POSITION_LABELS[state])
    return (
        f"Назначение: {identifier(target.kind)} {known_value(target.tag_known, target.tag, identifier, 'без тега')}; "
        f"позиция: {position}"
    )


def _route_outcome_lines(view: RouteExplanationView) -> Lines:
    outcome = view.outcome
    label = catalog_label(OUTCOME_LABELS, outcome.value) if type(outcome) is RouteOutcome else HIDDEN
    lines = [f"Итог: {label}"]
    selection = view.selection
    if outcome is RouteOutcome.POLICY_ABSENT:
        lines.append(INDENT + POLICY_ABSENT_NOTE)
    elif outcome is RouteOutcome.UNKNOWN or selection is None:
        lines.append(INDENT + f"Правило не выбрано: условие на шаге {count(len(view.steps))} неизвестно.")
        lines.append(INDENT + UNKNOWN_ROUTE_NOTE)
    else:
        position = _route_position(selection.index, selection.group_index, selection.offset)
        if outcome is RouteOutcome.FINAL:
            lines.append(
                INDENT + f"Ни одно включённое правило не совпало: действует финальное {position} — "
                f"действие {identifier(selection.action)}"
            )
        else:
            lines.append(
                INDENT + f"Выбрано {position}: действие {identifier(selection.action)}; "
                + _route_identity(selection.has_id, selection.rule_id, selection.has_name, selection.name)
            )
        lines.append(INDENT + _route_target_line(selection))
    return lines


def present_route_explanation(view: RouteExplanationView) -> Lines:
    """Показать предварительный расчёт маршрута: предположения, схему, шаги и один из четырёх итогов.

    Введённые домен и адреса, значения условий и коды наборов в представление
    не входят, поэтому вывести их нельзя; названия правил проходят фильтр
    `rule_name`, идентификаторы — `rule_id`, теги и части — свои фильтры.
    """
    if type(view) is not RouteExplanationView:
        raise TypeError("Ожидается RouteExplanationView.")
    lines = ["Предварительный расчёт маршрута", ROUTE_NOTE, "Предположения расчёта:"]
    lines += indented(safe_text(item) for item in view.assumptions)
    lines.append(f"Адресов в расчёте: {optional_count(view.ip_count)}")
    scheme = view.scheme
    if scheme is not None:
        policy = "собрана" if scheme.policy_present is True else "не собрана"
        lines.append(
            f"Схема: часть {optional_file_name(scheme.routing_part)}; только просмотр {flag(scheme.read_only)}; "
            f"групп {count(scheme.group_count)}; правил модели {count(scheme.rule_count)}; политика {policy}; "
            f"причины: {identifiers(scheme.reasons)}"
        )
        if scheme.api_service_group_count:
            lines.append(
                f"Служебных правил API вне расчёта: {count(scheme.api_service_group_count)} — "
                "они направляют трафик служебного inbound в обработчик API и в политику не входят"
            )
        lines += _metadata_state_lines(view.metadata_state, view.metadata_error)
    lines.append(f"Шагов проверки: {count(len(view.steps))}")
    lines += indented(_route_step_line(number, step) for number, step in enumerate(view.steps, start=1))
    lines += _route_outcome_lines(view)
    return lines


def route_layout(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    sections = []
    outcome = []
    for line, children in report_paragraphs(body):
        if line == "Предположения расчёта:" and children:
            sections.append(("Предположения расчёта", children))
        elif line.startswith("Шагов проверки: ") and children:
            summary.append(line)
            sections.append(("Шаги проверки", children))
        elif line.startswith("Итог: "):
            outcome.extend((line, *children))
        else:
            summary.extend((line, *children))
    return (*outcome, *summary), tuple(sections)


def bind_actions(
    bindings: SectionActions, proxy: InspectProxyConfigHandler, metadata: ManagerMetadataStore | None,
    geo_match: GeoDataSource | None, operation_ids: OperationIdFactory,
) -> None:
    """Подключить список и объяснение маршрута к одному сценарию импорта схемы."""
    routing = ImportRoutingSchemeHandler(proxy, operation_ids=operation_ids)
    rules = ListRoutingRulesHandler(routing, metadata, operation_ids=operation_ids)
    bindings["routing.list"] = lambda: present_result(rules.execute(ListRoutingRules()), present_rule_list)
    explain = ExplainRouteHandler.from_import(routing, metadata, geo_match, operation_ids=operation_ids)

    def explain_route(value: str) -> list[str]:
        return present_result(explain.execute(ExplainRoute(destination=value)), present_route_explanation)

    bindings["routing.explain"] = lambda: ValueRequest(ROUTE_PROMPT, explain_route)
