"""Список устройств, карточки и назначенные политики."""

import re

from keenvpn.application.contract import OperationIdFactory
from keenvpn.application.keenetic_devices import (
    ASSIGNMENT_LABELS, DeviceEntryView, DeviceListView, ListKeeneticDevices, ListKeeneticDevicesHandler,
    MAX_DEVICE_NAME_LENGTH, PRESENCE_LABELS, PRESENCE_REASON_LABELS, SEGMENT_MATCH_LABELS, SegmentMatch,
)
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler, KeeneticSegmentView, KeeneticStateView
from keenvpn.interfaces.cli.bindings import SectionActions
from keenvpn.interfaces.cli.menu import ListLayout, ListEntry, MAX_ITEM_NUMBER, MenuList
from keenvpn.interfaces.cli.presentation import (
    catalog_label, INDENT, user_text, count, flag, HIDDEN, identifier, identifiers, interface_id, known_value,
    Lines, optional_flag, optional_identifier, present_result, SNAPSHOT_NOTE,
)

ACTION_CAPTIONS = {
    "devices.list": "Снимок устройств Keenetic, их присутствия и назначенных политик.",
}

LIST_LAYOUT = ListLayout(
    title="Список устройств", preview_title="Выбрано устройство", empty_search="Устройства не найдены.",
    related_actions=("devices.assign", "devices.inherit"),
)


_MAC_IN_DEVICE_NAME = re.compile(
    r"(?=(?P<mac>[0-9a-f]{2}(?P<separator>[:-])[0-9a-f]{2}(?:(?P=separator)[0-9a-f]{2}){4}))",
    re.ASCII | re.IGNORECASE,
)
"""Шесть шестнадцатеричных пар с одним видом разделителя; поиск включает перекрывающиеся совпадения."""


def device_name(value: object) -> str:
    """Проверить формат имени регистрации и скрыть MAC-подстроки в показанном имени."""
    name = user_text(value, MAX_DEVICE_NAME_LENGTH)
    parts: list[str] = []
    end = 0
    for match in _MAC_IN_DEVICE_NAME.finditer(name):
        start, match_end = match.span("mac")
        # Перекрывающиеся совпадения объединяются в одну маску.
        if start >= end:
            parts.extend((name[end:start], "<MAC скрыт>"))
        end = match_end
    if not parts:
        return name
    return "".join(parts) + name[end:] + " (имя изменено для показа)"


def _segment_line(segment: KeeneticSegmentView) -> str:
    """Строка назначения сегмента: технический ID интерфейса после фильтра и признаки."""
    if type(segment) is not KeeneticSegmentView:
        return HIDDEN
    return (
        f"Сегмент {interface_id(segment.segment_id)}: назначение {identifier(segment.assignment)}, "
        f"политика {optional_identifier(segment.policy_id)}, запрет доступа {flag(segment.access_denied)}, "
        f"только просмотр {flag(segment.read_only)}"
    )


def present_keenetic_state(view: KeeneticStateView) -> Lines:
    """Показать политики, назначения сегментов и счётчики устройств без MAC, имён и адресов."""
    if type(view) is not KeeneticStateView:
        raise TypeError("Ожидается KeeneticStateView.")
    devices, registrations, runtime = view.devices, view.registrations, view.runtime
    lines = [
        "Keenetic",
        f"Политик: {count(view.policy_count)}; идентификаторы: {identifiers(view.policy_ids)}",
        f"Назначений сегментов: {count(len(view.segments))}; без политики: {count(view.segment_missing_policy_count)}",
    ]
    lines.extend(INDENT + _segment_line(segment) for segment in view.segments)
    lines += [
        f"Записи устройств: всего {count(devices.record_count)}, разных MAC {count(devices.distinct_mac_count)}, "
        f"online {count(devices.online_count)}, offline {count(devices.offline_count)}, "
        f"неизвестно {count(devices.unknown_count)}",
        f"{INDENT}Назначения: явных {count(devices.explicit_count)}, наследуют {count(devices.inherit_count)}, "
        f"без назначения {count(devices.unassigned_count)}, неизвестных {count(devices.unknown_assignment_count)}; "
        f"запрет доступа {count(devices.access_denied_count)}; только просмотр {count(devices.read_only_count)}",
        f"{INDENT}Связи: с регистрацией {count(devices.with_registration_count)}, "
        f"с наблюдением {count(devices.with_observation_count)}, "
        f"неоднозначных наблюдений {count(devices.ambiguous_observation_count)}, "
        f"расхождений наблюдений {count(devices.observation_mismatch_count)}, "
        f"без политики {count(devices.missing_policy_count)}",
        f"Регистрации: всего {count(registrations.registration_count)}, "
        f"разных MAC {count(registrations.distinct_mac_count)}, повторов MAC {count(registrations.duplicate_mac_count)}, "
        f"нераспознанных {count(registrations.unresolvable_count)}, "
        f"без записи устройства {count(registrations.without_device_count)}",
        f"Наблюдения: всего {count(runtime.record_count)}, разных MAC {count(runtime.distinct_mac_count)}, "
        f"повторов MAC {count(runtime.duplicate_mac_count)}, нераспознанных {count(runtime.unresolvable_count)}, "
        f"активных {count(runtime.active_count)}, зарегистрированных {count(runtime.registered_count)}, "
        f"без записи устройства {count(runtime.without_device_count)}",
    ]
    return lines

DEVICES_LIST_TITLE = "Устройства"

DEVICES_ITEM_NAME = "Устройство"

POLICY_IDS_PER_LINE = 10
"""Сколько ID политик в одной вводной строке: ID после фильтра не длиннее 64 символов, строка остаётся в пределе."""

DEVICES_NOTE = (
    "Поля MAC, имён хостов, адресов и описаний политик скрыты. "
    "В именах регистраций последовательности из шести шестнадцатеричных пар через двоеточия или дефисы маскируются."
)

SEGMENT_MATCH_NOTE = (
    "Сегмент сопоставлен по техническому ID наблюдаемого интерфейса: это не состав сегмента "
    "и не действующая политика устройства."
)


def _device_name_text(item: DeviceEntryView) -> str:
    absent = "без регистрации" if item.registration_count == 0 else f"регистраций {count(item.registration_count)}"
    return known_value(item.name_known, item.name, device_name, absent)


def _device_assignment(item: DeviceEntryView) -> str:
    text = catalog_label(ASSIGNMENT_LABELS, item.assignment)
    if item.policy_id is not None:
        text += f" {identifier(item.policy_id)}"
    if item.policy_present is False:
        text += " (нет в списке политик)"
    return text


def _device_interface(item: DeviceEntryView) -> str:
    return known_value(item.observed_interface_known, item.observed_interface_id, interface_id, "не наблюдался")


def _device_label(item: DeviceEntryView) -> str:
    return (
        f"{_device_name_text(item)}: {_device_assignment(item)}, {catalog_label(PRESENCE_LABELS, item.presence)}, "
        f"запрет доступа {flag(item.access_denied)}, интерфейс {_device_interface(item)}"
    )


def _policy_lines(view: DeviceListView) -> Lines:
    # Число политик задаёт роутер, поэтому идентификаторы идут строками по POLICY_IDS_PER_LINE.
    lines = [f"Политик: {count(view.policy_count)}"]
    if not view.policy_ids:
        lines.append(INDENT + "нет")
    for start in range(0, len(view.policy_ids), POLICY_IDS_PER_LINE):
        lines.append(INDENT + identifiers(view.policy_ids[start:start + POLICY_IDS_PER_LINE]))
    return lines


def _device_card(item: DeviceEntryView) -> tuple[str, ...]:
    registrations = [f"Регистраций: {count(item.registration_count)}"]
    registrations.extend(INDENT + device_name(name) for name in item.registration_names)
    reason = "нет" if item.presence_reason is None else catalog_label(PRESENCE_REASON_LABELS, item.presence_reason)
    segment = [f"Сегмент по интерфейсу: {catalog_label(SEGMENT_MATCH_LABELS, item.segment_match)}"]
    if item.segment_match == SegmentMatch.MATCHED.value:
        segment.append(INDENT + _segment_line(item.segment))
    return (
        f"Позиция записи: {count(item.position)} (счёт с нуля в ip/hotspot)",
        *registrations,
        f"Назначение: {identifier(item.assignment)} — {_device_assignment(item)}; "
        f"в списке политик: {optional_flag(item.policy_present)}",
        f"Online: {catalog_label(PRESENCE_LABELS, item.presence)}; причина: {reason}",
        f"Запрет доступа: {flag(item.access_denied)}; только просмотр: {flag(item.read_only)}; "
        f"MAC повторяется: {flag(item.mac_duplicate)}",
        f"Наблюдаемый интерфейс: {_device_interface(item)}",
        *segment,
        SEGMENT_MATCH_NOTE,
        DEVICES_NOTE,
    )


def _device_entry(number: int, item: DeviceEntryView) -> ListEntry:
    name = _device_name_text(item)
    presence = catalog_label(PRESENCE_LABELS, item.presence)
    assignment = _device_assignment(item)
    brief = f"{name} · {presence} · {assignment}"
    preview = [f"Имя регистрации: {name}", f"Присутствие: {presence}", f"Индивидуальное назначение: {assignment}",
               "Запрет доступа: " + ("включён" if item.access_denied else "выключен"),
               f"Наблюдаемый интерфейс: {_device_interface(item)}"]
    if item.presence_reason is not None:
        preview.append("Причина состояния: " + catalog_label(PRESENCE_REASON_LABELS, item.presence_reason))
    if item.read_only:
        preview.append("Только для просмотра.")
    return ListEntry(number, _device_label(item), _device_card(item), brief=brief, preview=tuple(preview))


def present_device_list(view: DeviceListView) -> MenuList:
    """Показать записи устройств списком: номер — позиция записи в `ip/hotspot.host`, начиная с 1.

    Строка списка и карточка собраны из одних отфильтрованных значений: имя
    регистрации после проверки формата и маскирования MAC, подписи каталогов application для назначения,
    online и сопоставления сегмента, технические ID после проверки формата.
    Поля MAC, имён хостов и адресов в представление не входят.
    """
    if type(view) is not DeviceListView:
        raise TypeError("Ожидается DeviceListView.")
    counts = view.counts
    header = [
        "Устройства Keenetic по прочитанному состоянию",
        *_policy_lines(view),
        f"Назначений сегментов: {count(len(view.segments))}; без политики в списке: "
        f"{count(view.segment_missing_policy_count)}",
        *(INDENT + _segment_line(segment) for segment in view.segments),
        f"Записей устройств: всего {count(counts.record_count)}; online {count(counts.online_count)}, "
        f"offline {count(counts.offline_count)}, online неизвестно {count(counts.unknown_count)}; "
        f"разных MAC {count(counts.distinct_mac_count)}, записей с повтором MAC {count(counts.duplicate_mac_count)}",
        f"Назначения: явных {count(counts.explicit_count)}, наследуют {count(counts.inherit_count)}, "
        f"без назначения {count(counts.unassigned_count)}, не распознано {count(counts.unknown_assignment_count)}; "
        f"политики нет в списке {count(counts.missing_policy_count)}; запрет доступа {count(counts.access_denied_count)}; "
        f"только просмотр {count(counts.read_only_count)}",
        f"Регистраций без записи: {count(counts.registrations_without_device_count)}; "
        f"наблюдений без записи: {count(counts.runtime_without_device_count)}; "
        f"неоднозначных наблюдений: {count(counts.ambiguous_observation_count)}; "
        f"скрытых имён: {count(counts.hidden_name_count)}",
        DEVICES_NOTE,
        SNAPSHOT_NOTE,
    ]
    summary = [f"Записей устройств: {count(counts.record_count)} · Политик: {count(view.policy_count)}",
               f"Online: {count(counts.online_count)} · Offline: {count(counts.offline_count)} · "
               f"Неизвестно: {count(counts.unknown_count)}"]
    items = view.devices[:MAX_ITEM_NUMBER]
    if len(view.devices) > MAX_ITEM_NUMBER:
        header.append(f"Записей больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.")
        summary.append(header[-1])
    entries = tuple(_device_entry(number, item) for number, item in enumerate(items, start=1))
    return MenuList(DEVICES_LIST_TITLE, DEVICES_ITEM_NAME, tuple(header), entries, summary=tuple(summary))


def bind_actions(bindings: SectionActions, keenetic: InspectKeeneticStateHandler, operation_ids: OperationIdFactory) -> None:
    """Подключить список устройств к общему источнику состояния Keenetic."""
    devices = ListKeeneticDevicesHandler(keenetic, operation_ids=operation_ids)
    bindings["devices.list"] = lambda: present_result(devices.execute(ListKeeneticDevices()), present_device_list)
