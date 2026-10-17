"""Текстовые представления результатов сценариев для терминала.

Представления получают только безопасные данные `Result` и переносят их
в строки с фиксированными русскими подписями. Строки из источников попадают
в вывод только после проверки формата своего вида: теги и коды, имена файлов,
интерфейсы сегментов, хеши, источник и версия геобазы. Правило тегов не допускает
`.`, `:`, `/` и `@`, поэтому домены, адреса, MAC, пути и URL, записанные в тег,
не выводятся. Значение вне формата заменяется пометкой. Управляющие символы и ANSI
не используются, данные не вычисляются и не дополняются: показывается лишь то,
что вернул сценарий.
"""

from collections.abc import Callable, Iterable
import re

from keenvpn.application.contract import CONTRACT_VERSION, ErrorDetail, Result
from keenvpn.application.installation import GeoDataView, InstallationView, XrayProcessView
from keenvpn.application.keenetic_state import KeeneticStateView
from keenvpn.application.manager_metadata import ManagerMetadataStatusView
from keenvpn.application.proxy_config import ProxyConfigView, XKeenFlagView, XKeenListView
from keenvpn.application.routing_import import RoutingSchemeView
from keenvpn.interfaces.cli.terminal import UNAVAILABLE_MARK


Lines = list[str]
Presenter = Callable[[object], Lines]

HIDDEN = "<скрыто>"
"""Пометка вместо строки, не прошедшей проверку формата."""
MISSING = "нет данных"
"""Пометка вместо отсутствующего значения."""
MAX_TEXT_LENGTH = 500
_INDENT = "  "

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,63}")
"""Тег, код, состояние: правило `safe_identifier` домена — без `.`, `:`, `/`, `@` и пробелов."""
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,58}\.(?:json|dat)")
"""Имя части Xray или файла геобазы: без каталога, только расширения `.json` и `.dat`."""
_INTERFACE_ID = re.compile(r"(?=.{1,64}\Z)[A-Za-z][A-Za-z0-9]*(?:[/.][A-Za-z0-9]+)*")
"""Интерфейс сегмента Keenetic вида `Bridge0` или `GigabitEthernet0/Vlan1`: с буквы, без `:` и пробелов."""
_DIGEST = re.compile(r"[0-9a-f]{64}")
"""SHA-256 в нижнем регистре."""
_GEO_SOURCE = re.compile(
    r"(?=.{1,128}\Z)(?:[A-Za-z0-9][A-Za-z0-9_+-]*(?:\.[A-Za-z0-9_+-]+)*"
    r"|https?://[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?)"
)
"""Источник геобазы в форме, которую оставляет домен: идентификатор либо схема и хост без пути."""
_GEO_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
"""Версия геобазы: короткий идентификатор, как у домена."""


def _shown(pattern: re.Pattern[str], value: object) -> str:
    if type(value) is str and pattern.fullmatch(value) is not None:
        return value
    return HIDDEN


def identifier(value: object) -> str:
    """Показать тег, код или состояние только в формате технического идентификатора; иначе пометку."""
    return _shown(_IDENTIFIER, value)


def file_name(value: object) -> str:
    """Показать имя части Xray или файла геобазы; иначе пометку."""
    return _shown(_FILE_NAME, value)


def optional_file_name(value: object) -> str:
    """Имя файла или пометка отсутствия."""
    return MISSING if value is None else file_name(value)


def interface_id(value: object) -> str:
    """Показать идентификатор интерфейса сегмента Keenetic; иначе пометку."""
    return _shown(_INTERFACE_ID, value)


def digest(value: object) -> str:
    """Показать SHA-256; иначе пометку."""
    return _shown(_DIGEST, value)


def optional_digest(value: object) -> str:
    """SHA-256 или пометка отсутствия."""
    return MISSING if value is None else digest(value)


def geo_source(value: object) -> str:
    """Показать источник геобазы в форме домена; иначе пометку."""
    return _shown(_GEO_SOURCE, value)


def geo_version(value: object) -> str:
    """Показать версию геобазы в форме домена; иначе пометку."""
    return _shown(_GEO_VERSION, value)


def optional_identifier(value: object) -> str:
    """Идентификатор или пометка отсутствия."""
    return MISSING if value is None else identifier(value)


def identifiers(values: Iterable[object]) -> str:
    """Перечислить идентификаторы через запятую; пустой список — «нет»."""
    items = [identifier(value) for value in values]
    return ", ".join(items) if items else "нет"


def known_value(known: object, value: object, show: Callable[[object], str], absent: str) -> str:
    """Различить отсутствие значения и известное, но скрытое сценарием значение.

    `known=False` — значения нет, показывается `absent`; `known=True` и `None` —
    значение задано, но application скрыл его как небезопасное, показывается
    пометка `<скрыто>`; иначе значение проходит фильтр своего вида.
    """
    if known is False:
        return absent
    if known is True:
        return HIDDEN if value is None else show(value)
    return HIDDEN


def flag(value: object) -> str:
    """Показать логическое значение словами; другой тип — пометка."""
    if type(value) is bool:
        return "да" if value else "нет"
    return HIDDEN


def optional_flag(value: object) -> str:
    """Логическое значение или пометка отсутствия."""
    return MISSING if value is None else flag(value)


def count(value: object) -> str:
    """Показать целое число; другой тип, включая bool, — пометка."""
    return str(value) if type(value) is int else HIDDEN


def optional_count(value: object) -> str:
    """Целое число или пометка отсутствия."""
    return MISSING if value is None else count(value)


def safe_text(value: object) -> str:
    """Показать заранее заданный текст сценария, если он печатный и не слишком длинный."""
    if type(value) is str and 0 < len(value) <= MAX_TEXT_LENGTH and value.isprintable():
        return value
    return HIDDEN


def _indent(lines: Iterable[str], level: int = 1) -> Lines:
    return [_INDENT * level + line for line in lines]


def present_error(error: ErrorDetail) -> Lines:
    """Показать отказ сценария: категорию, код, уточнение и заранее заданный текст."""
    if type(error) is not ErrorDetail:
        raise TypeError("Ожидается ErrorDetail.")
    lines = [f"Отказ: {identifier(error.category.value)} / {identifier(error.code)}"]
    if error.reason is not None:
        lines.append(f"Уточнение: {identifier(error.reason)}")
    lines.append(f"Причина: {safe_text(error.message)}")
    return lines


def present_result(result: Result, present: Presenter) -> Lines:
    """Показать результат: данные через переданное представление, отказ — общим способом."""
    if type(result) is not Result:
        raise TypeError("Ожидается Result сценария.")
    if result.succeeded:
        return present(result.data)
    return present_error(result.error)


def _flag_view(value: XKeenFlagView) -> str:
    return f"{identifier(value.status)} ({optional_identifier(value.value)})"


def _list_view(label: str, value: XKeenListView) -> str:
    return (
        f"{label}: строк {count(value.line_count)}, записей {count(value.entry_count)}, "
        f"портов {optional_count(value.port_count)}, диапазонов {optional_count(value.range_count)}, "
        f"адресов {optional_count(value.address_count)}, некорректных {count(value.invalid_count)}"
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
    for segment in view.segments:
        lines.append(
            f"{_INDENT}Сегмент {interface_id(segment.segment_id)}: назначение {identifier(segment.assignment)}, "
            f"политика {optional_identifier(segment.policy_id)}, запрет доступа {flag(segment.access_denied)}, "
            f"только просмотр {flag(segment.read_only)}"
        )
    lines += [
        f"Записи устройств: всего {count(devices.record_count)}, разных MAC {count(devices.distinct_mac_count)}, "
        f"online {count(devices.online_count)}, offline {count(devices.offline_count)}, "
        f"неизвестно {count(devices.unknown_count)}",
        f"{_INDENT}Назначения: явных {count(devices.explicit_count)}, наследуют {count(devices.inherit_count)}, "
        f"без назначения {count(devices.unassigned_count)}, неизвестных {count(devices.unknown_assignment_count)}; "
        f"запрет доступа {count(devices.access_denied_count)}; только просмотр {count(devices.read_only_count)}",
        f"{_INDENT}Связи: с регистрацией {count(devices.with_registration_count)}, "
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


def present_proxy_summary(view: ProxyConfigView) -> Lines:
    """Показать структурную сводку Xray и XKeen без доменов, адресов, путей и паролей."""
    if type(view) is not ProxyConfigView:
        raise TypeError("Ожидается ProxyConfigView.")
    xray, xkeen = view.xray, view.xkeen
    return [
        "Xray",
        f"Частей: {count(xray.part_count)}; разделов верхнего уровня: {count(len(xray.sections))}; "
        f"повторяющихся разделов: {count(len(xray.duplicate_sections))}",
        f"Inbound: {count(len(xray.inbounds))}; outbound: {count(len(xray.outbounds))}; "
        f"балансировщиков: {count(len(xray.balancers))}; правил маршрутизации: {count(xray.rule_count)}",
        f"DNS-теги: {identifiers(xray.dns_tags)}; стратегии доменов: {identifiers(xray.domain_strategies)}",
        f"Неподдержанных мест конфигурации: {count(len(xray.unsupported_paths))}",
        "XKeen",
        f"kill-switch: {_flag_view(xkeen.settings.killswitch)}; присваиваний init: {count(xkeen.init.assignment_count)}; "
        f"повторов имён init: {count(len(xkeen.init.duplicate_names))}",
        _list_view("Список исключённых портов", xkeen.port_exclude),
        _list_view("Список перехватываемых портов", xkeen.port_proxying),
        _list_view("Список исключённых адресов", xkeen.ip_exclude),
    ]


def present_port53(view: ProxyConfigView) -> Lines:
    """Показать раздельные факты о порту 53 из файлов XKeen; фактический перехват не проверяется."""
    if type(view) is not ProxyConfigView:
        raise TypeError("Ожидается ProxyConfigView.")
    facts = view.xkeen.port_53
    return [
        "Порт 53 по файлам конфигурации XKeen",
        f"Запись {count(facts.port)} в списке исключённых портов: {flag(facts.port_exclude_entry)}; "
        f"диапазон с этим портом: {flag(facts.port_exclude_range)}",
        f"Запись {count(facts.port)} в списке перехватываемых портов: {flag(facts.port_proxying_entry)}; "
        f"диапазон с этим портом: {flag(facts.port_proxying_range)}",
        f"proxy_dns: {_flag_view(facts.proxy_dns)}; proxy_router: {_flag_view(facts.proxy_router)}",
        _list_view("Список исключённых портов", view.xkeen.port_exclude),
        _list_view("Список перехватываемых портов", view.xkeen.port_proxying),
        "Фактический перехват DNS не проверялся: это факты файлов, а не состояние трафика. "
        "Отсутствие исключения само по себе не ошибка и не доказательство перехвата.",
    ]


def present_geodata(view: GeoDataView) -> Lines:
    """Показать инвентарь файлов геобаз и ссылки правил без кодов наборов."""
    if type(view) is not GeoDataView:
        raise TypeError("Ожидается GeoDataView.")
    lines = [
        "Геобазы",
        f"Файлов найдено: {count(view.present_count)}; отсутствует: {count(view.missing_count)}; "
        f"лишних: {count(view.extra_count)}",
    ]
    for item in view.files:
        source = known_value(item.source_known, item.source, geo_source, "неизвестен")
        version = known_value(item.version_known, item.version, geo_version, "неизвестна")
        lines.append(
            f"{_INDENT}{file_name(item.name)}: {'найден' if item.present is True else 'отсутствует'}, "
            f"размер {optional_count(item.size)}, SHA-256 {optional_digest(item.sha256)}, "
            f"источник {source}, версия {version}, ссылок {count(item.reference_count)}, "
            f"наборов {count(item.set_count)}"
        )
    lines.append(
        f"Ссылок правил и DNS на наборы: {count(view.reference_count)}; сопоставлено {count(view.resolved_count)}; "
        f"не сопоставлено {count(view.unresolved_count)}; неподдержанных {count(len(view.unsupported_references))}"
    )
    return lines


def present_xray_process(view: XrayProcessView) -> Lines:
    """Показать наблюдение процесса Xray; ни одно состояние не подтверждает работу VPN."""
    if type(view) is not XrayProcessView:
        raise TypeError("Ожидается XrayProcessView.")
    return [
        "Процесс Xray",
        f"Состояние: {identifier(view.state)}; процессов: {count(view.process_count)}; "
        f"маркер готовности: {flag(view.ready_marker)}; согласовано: {flag(view.consistent)}",
    ]


def present_installation(view: InstallationView) -> Lines:
    """Показать сводку прочитанной установки из четырёх областей."""
    if type(view) is not InstallationView:
        raise TypeError("Ожидается InstallationView.")
    return [
        "Сводка установки по прочитанным источникам",
        *_indent(present_keenetic_state(view.keenetic)),
        *_indent(present_proxy_summary(view.proxy)),
        *_indent(present_geodata(view.geodata)),
        *_indent(present_xray_process(view.xray_process)),
        "Это снимок источников на момент чтения: работу VPN, перехват трафика и маршрут клиента он не подтверждает.",
    ]


def present_routing_scheme(view: RoutingSchemeView) -> Lines:
    """Показать импортированные группы правил без доменов, адресов и кодов наборов."""
    if type(view) is not RoutingSchemeView:
        raise TypeError("Ожидается RoutingSchemeView.")
    lines = [
        "Правила маршрутизации по конфигурации Xray",
        f"Часть с маршрутизацией: {optional_file_name(view.routing_part)}; частей с разделом routing: "
        f"{count(len(view.routing_parts))}",
        f"Групп правил: {count(view.group_count)}; правил модели: {count(view.rule_count)}; "
        f"финальное действие: {'не определено' if view.final_action is None else identifier(view.final_action)}",
        f"Только для просмотра: {flag(view.read_only)}; причины: {identifiers(view.reasons)}",
    ]
    policy = view.policy
    if policy is None:
        lines.append("Политика маршрутизации не собрана: схема доступна только для просмотра.")
    else:
        lines.append(
            f"Политика: правил {count(policy.rule_count)}, включено {count(policy.active_rule_count)}, "
            f"служебных {count(policy.protected_rule_count)}, финальное действие {identifier(policy.final_action)}, "
            f"только просмотр {flag(policy.read_only)}"
        )
    for group in view.groups:
        types = ", ".join(f"{identifier(item.name)} {count(item.count)}" for item in group.condition_types) or "нет"
        line = (
            f"{count(group.index)}. {identifier(group.kind)}: условий {count(group.condition_count)} ({types}), "
            f"значений {count(group.value_count)}, действие "
            f"{'нет' if group.action is None else identifier(group.action)}, назначение "
            f"{identifier(group.target.kind)} {known_value(group.target.tag_known, group.target.tag, identifier, 'без тега')}, "
            f"только просмотр {flag(group.read_only)}"
        )
        if group.reasons:
            line += f", причины: {identifiers(group.reasons)}"
        if group.target.reasons:
            line += f", причины назначения: {identifiers(group.target.reasons)}"
        if group.value_reasons:
            # Пути значений не выводятся: они ведут к условиям, а для диагностики достаточно кодов.
            counts: dict[str, int] = {}
            for item in group.value_reasons:
                code = identifier(item.reason)
                counts[code] = counts.get(code, 0) + 1
            line += ", причины значений: " + ", ".join(f"{code} ×{number}" for code, number in counts.items())
        if group.unknown_field_count:
            line += f", неизвестных полей {count(group.unknown_field_count)}"
        lines.append(_INDENT + line)
    return lines


def present_manager_metadata(view: ManagerMetadataStatusView) -> Lines:
    """Показать метаданные менеджера без путей, идентификаторов хранилищ и ревизии."""
    if type(view) is not ManagerMetadataStatusView:
        raise TypeError("Ожидается ManagerMetadataStatusView.")
    lines = ["Метаданные менеджера"]
    if view.present is not True or view.metadata is None:
        lines.append("Метаданных нет: размещение хранилищ ещё не записано.")
        return lines
    metadata = view.metadata
    lines.append(
        f"Версия схемы: {count(metadata.schema_version)}; неизвестных полей: {count(metadata.unknown_field_count)}"
    )
    storage = metadata.storage
    if storage is None:
        lines.append("Размещение хранилищ не записано.")
        return lines
    lines.append(
        f"Вариант хранения: {identifier(storage.variant_state)} {optional_identifier(storage.variant)}; "
        f"различных хранилищ: {count(storage.distinct_storage_count)}"
    )
    for role in storage.roles:
        lines.append(
            f"{_INDENT}Роль {identifier(role.role)}: состояние {identifier(role.state)}, "
            f"идентификатор {optional_identifier(role.storage_id_state)}, путь {optional_identifier(role.path_state)}, "
            f"проверено {optional_flag(role.verified)}"
        )
    limits = storage.history_limits
    lines.append(
        f"История: размер {identifier(limits.size_state)} {optional_count(limits.size_bytes)} байт; "
        f"срок {identifier(limits.retention_state)} {optional_count(limits.retention_seconds)} с"
    )
    return lines


def present_about() -> Lines:
    """Справка по навигации и версия контракта результатов."""
    return [
        "Справка по меню KeenVPN",
        "Выберите пункт, введя его номер и Enter. 0 возвращает на уровень выше, в корневом меню — завершает работу.",
        f"Пункты с пометкой {UNAVAILABLE_MARK} не выполняются: при выборе показывается причина, настройки не меняются.",
        "Меню только показывает данные подключённых источников чтения; конфигурация роутера, Xray и XKeen не изменяется.",
        f"Версия контракта результатов прикладных сценариев: {CONTRACT_VERSION}",
    ]
