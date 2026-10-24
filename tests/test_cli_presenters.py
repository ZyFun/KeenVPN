"""Текстовые представления результатов на обезличенном снимке: подписи, безопасность, отказы."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import (
    CONTRACT_VERSION, NEXT_STEP_MESSAGES, ErrorCategory, ErrorCode, ErrorDetail, NextStepCode, Result, failed, succeeded,
)
from dataclasses import replace

from keenvpn.application.checks import CHECK_STATUS_LABELS, VPN_REACHABLE_CHECK, XRAY_PROCESS_CHECK, CheckView, ChecksView
from keenvpn.application.contract import CheckStatus
from keenvpn.application.installation import GeoDatabaseFileView, InspectInstallation, InspectInstallationHandler
from keenvpn.application.keenetic_state import InspectKeeneticState, InspectKeeneticStateHandler
from keenvpn.application.manager_metadata import (
    ImportStoragePlacement, ImportStoragePlacementHandler, InspectManagerMetadata, InspectManagerMetadataHandler,
)
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler, XrayPositionView
from keenvpn.application.proxy_connections import (
    BalancerConnectionView, ConnectionsView, InspectConnections, InspectConnectionsHandler, OutboundConnectionView,
)
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler
from keenvpn.application.routing_rules import (
    ListRoutingRules, ListRoutingRulesHandler, MetadataState, RuleGroupIdentityView, RuleListEntryView,
    TargetPositionState,
)
from keenvpn.domain.manager_metadata import ManagerMetadata, RuleRecord, UnknownFields, encode_manager_metadata
from keenvpn.domain.rule_binding import rule_key, scheme_rules
from keenvpn.domain.routing_import import import_routing_scheme
from keenvpn.application.quick_check import QuickCheck, QuickCheckHandler
from keenvpn.application.status_summary import PORT_53_HINT, InspectStatusSummary, InspectStatusSummaryHandler
from keenvpn.domain.xray_process import XrayProcessObservation
from keenvpn.interfaces.cli.presenters import DNS_PRITUNL_NOTE, PORT_53_NOTE, SNAPSHOT_NOTE, present_quick_check
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.interfaces.cli import presenters
from keenvpn.interfaces.cli.presenters import present_status_header, present_status_summary
from keenvpn.interfaces.cli.presenters import (
    HIDDEN, MISSING, count, digest, file_name, flag, geo_source, geo_version, identifier, identifiers, interface_id,
    check_status, known_value, optional_count, optional_digest, optional_file_name, optional_flag, optional_identifier, present_about, present_checks, present_error, present_geodata, present_installation, present_keenetic_state,
    present_manager_metadata, present_port53, present_proxy_summary, present_result, present_routing_scheme,
    present_xray_process, safe_text,
)
from keenvpn.interfaces.cli.presenters import (
    CONNECTIONS_HEALTH_NOTE, CONNECTIONS_ITEM_NAME, CONNECTIONS_LIST_TITLE, CONNECTIONS_NOTE, METADATA_NOTES,
    NAMES_PER_LABEL, SELECTORS_PER_LINE, TARGET_POSITION_LABELS, present_connections, present_rule_list, rule_id,
    rule_name,
)
from keenvpn.interfaces.cli.menu import MAX_ITEM_NUMBER, MAX_LIST_LINE_LENGTH, MenuList
from keenvpn.interfaces.cli.presenters import ROUTING_ITEM_NAME, ROUTING_LIST_TITLE
from keenvpn.application.keenetic_devices import (
    DeviceCountsView, DeviceEntryView, DeviceListView, ListKeeneticDevices, ListKeeneticDevicesHandler,
)
from keenvpn.application.keenetic_state import KeeneticSegmentView
from keenvpn.interfaces.cli.presenters import (
    DEVICES_ITEM_NAME, DEVICES_LIST_TITLE, DEVICES_NOTE, SEGMENT_MATCH_NOTE, device_name, present_device_list,
)
from keenvpn.interfaces.cli.terminal import UNAVAILABLE_MARK
from keenvpn.application.routing import OUTCOME_LABELS, ExplainRoute, ExplainRouteHandler, RouteOutcome
from keenvpn.domain.routing import IPCondition, RoutingAction, RoutingRule
from keenvpn.domain.routing_policy import FinalRoutingRule, RoutingPolicy
from keenvpn.interfaces.cli.presenters import (
    POLICY_ABSENT_NOTE, ROUTE_NOTE, UNKNOWN_ROUTE_NOTE, present_route_explanation,
)
from tests.support.in_memory import InMemoryRoutingPolicySource
from enum import StrEnum
import json

from keenvpn.adapters.xray_configs import xray_config_from_files
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure
from tests.support.in_memory import InMemoryManagerMetadataStore, InMemoryStoragePlacementSource
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import (
    SYNTHETIC_GEOIP_SHA256, SYNTHETIC_HISTORY_RETENTION, SYNTHETIC_HISTORY_SIZE, SYNTHETIC_STORAGE_ID,
    SYNTHETIC_STORAGE_ROOT, load_xray_snapshot_files, snapshot_installation_sources, snapshot_xray_config,
    synthetic_storage_placement,
)


PRIVATE_MARKERS = (
    "02:00:00:54", "02:00:00:00", "device-", "192.0.2.", "2001:db8", "fixture-policy", "fixture-interface",
    "fixture-private", "host-0", "host-1", "fixture-password", "/fixture/ws", "fixture-rule", "probe.example",
    "127.0.0.1", "/opt/var/log", "1181", "1191", "Обезличенный", "geoip:", "geosite:", "domain:", '"ru"', '"RU"',
    "fixture-set", "../", "fixture-user", "fixture-token", "fixture-query", "fixture-fragment", "token=",
    SYNTHETIC_STORAGE_ROOT, SYNTHETIC_STORAGE_ID, "\x1b",
)


def list_lines(groups: MenuList) -> list[str]:
    """Все строки списка: вводные, строки элементов и карточки."""
    return [*groups.header, *(entry.label for entry in groups.entries), *(line for entry in groups.entries for line in entry.card)]


def snapshot_results() -> dict[str, Result]:
    """Результаты пяти сценариев просмотра на снимке и искусственных источниках."""
    sources = snapshot_installation_sources()
    keenetic = InspectKeeneticStateHandler(
        sources.keenetic.policies, sources.keenetic.hotspot, sources.keenetic.registrations, sources.keenetic.runtime,
    )
    proxy = InspectProxyConfigHandler(sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists)
    installation = InspectInstallationHandler(keenetic, proxy, sources.geodata, sources.process)
    store = InMemoryManagerMetadataStore()
    ImportStoragePlacementHandler(
        InMemoryStoragePlacementSource(synthetic_storage_placement()), store,
    ).execute(ImportStoragePlacement())
    return {
        "installation": installation.execute(InspectInstallation()),
        "keenetic": keenetic.execute(InspectKeeneticState()),
        "proxy": proxy.execute(InspectProxyConfig()),
        "routing": ImportRoutingSchemeHandler(proxy).execute(ImportRoutingScheme()),
        "metadata": InspectManagerMetadataHandler(store).execute(InspectManagerMetadata()),
        "no_metadata": InspectManagerMetadataHandler(InMemoryManagerMetadataStore()).execute(InspectManagerMetadata()),
    }


class PresenterAssertions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = snapshot_results()
        for name, result in cls.results.items():
            assert result.succeeded, name

    def assert_safe_lines(self, lines):
        self.assertIsInstance(lines, list)
        self.assertTrue(lines)
        text = "\n".join(lines)
        for line in lines:
            self.assertIsInstance(line, str)
            self.assertTrue(line.isprintable(), line)
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        return text


class _OddCode(StrEnum):
    """Код-перечисление вне формата идентификатора: проверка, что фильтр действует и на значение."""

    BAD = "bad code!"


class SnapshotPresenterTests(PresenterAssertions):
    def test_installation_summary_names_four_areas_and_disclaimer(self):
        view = self.results["installation"].data
        with forbid_external_effects():
            lines = present_installation(view)
        text = self.assert_safe_lines(lines)
        self.assertEqual(lines[0], "Сводка установки по прочитанным источникам")
        for area in ("  Keenetic", "  Xray", "  XKeen", "  Геобазы", "  Процесс Xray", "  Проверки"):
            self.assertIn(area, lines)
        self.assertIn("  Активная сетевая проверка: не выполнялась", lines)
        self.assertIn("    xray_process_consistent: успешно", lines)
        self.assertIn("    geodata_references_resolved: успешно", lines)
        self.assertIn("    vpn_reachable: не проверено, причина network_check_not_performed (сетевая проверка)", lines)
        self.assertLess(lines.index("  Проверки"), len(lines) - 1)
        self.assertIn("Политик: 3; идентификаторы: Policy10, Policy20, Policy30", text)
        self.assertIn("Состояние: running; процессов: 1; маркер готовности: да; согласовано: да", text)
        self.assertIn(f"geoip.dat: найден, размер 1024, SHA-256 {SYNTHETIC_GEOIP_SHA256}", text)
        self.assertIn("geosite.dat: отсутствует, размер нет данных, SHA-256 нет данных", text)
        self.assertIn("источник fixture-geo-source, версия неизвестна", text)
        self.assertIn("работу VPN, перехват трафика и маршрут клиента он не подтверждает", lines[-1])
        self.assertIn("kill-switch: present (on)", text)

    def test_keenetic_state_shows_counts_and_segments_only(self):
        view = self.results["keenetic"].data
        with forbid_external_effects():
            lines = present_keenetic_state(view)
        text = self.assert_safe_lines(lines)
        self.assertEqual(lines[0], "Keenetic")
        self.assertEqual(len([line for line in lines if line.startswith("  Сегмент ")]), len(view.segments))
        for segment in view.segments:
            self.assertIn(f"Сегмент {segment.segment_id}: назначение {segment.assignment}", text)
        self.assertIn(f"Записи устройств: всего {view.devices.record_count}", text)
        self.assertIn(f"Регистрации: всего {view.registrations.registration_count}", text)
        self.assertIn(f"Наблюдения: всего {view.runtime.record_count}", text)

    def test_proxy_summary_and_port53_facts(self):
        view = self.results["proxy"].data
        with forbid_external_effects():
            summary = present_proxy_summary(view)
            port53 = present_port53(view)
        summary_text = self.assert_safe_lines(summary)
        port53_text = self.assert_safe_lines(port53)
        self.assertIn(f"Частей: {view.xray.part_count}", summary_text)
        self.assertIn(f"правил маршрутизации: {view.xray.rule_count}", summary_text)
        self.assertRegex(summary_text, r"kill-switch: [a-z_]+ \((on|off|нет данных)\)")
        self.assertEqual(port53[0], "Порт 53 по файлам конфигурации XKeen")
        self.assertIn("Запись 53 в списке исключённых портов: да", port53_text)
        self.assertIn("Запись 53 в списке перехватываемых портов: нет", port53_text)
        self.assertRegex(port53_text, r"proxy_dns: [a-z_]+ \((on|off|нет данных)\); proxy_router: [a-z_]+ \(")
        self.assertIn("Фактический перехват DNS не проверялся", port53[-1])
        self.assertIn("Отсутствие исключения само по себе не ошибка", port53[-1])

    def test_routing_scheme_lists_groups_without_values(self):
        view = self.results["routing"].data
        with forbid_external_effects():
            groups = present_routing_scheme(view)
        self.assertIs(type(groups), MenuList)
        self.assertEqual((groups.title, groups.item_name), (ROUTING_LIST_TITLE, ROUTING_ITEM_NAME))
        text = self.assert_safe_lines(list_lines(groups))
        self.assertEqual(groups.header[0], "Правила маршрутизации по конфигурации Xray")
        self.assertIn(f"Групп правил: {view.group_count}; правил модели: {view.rule_count}", text)
        self.assertIn("Политика маршрутизации не собрана", text)
        # Номер группы — позиция в схеме с 1: 0 зарезервирован за возвратом.
        self.assertEqual([entry.number for entry in groups.entries], list(range(1, len(view.groups) + 1)))
        for entry, group in zip(groups.entries, view.groups):
            for reason in group.reasons:
                self.assertIn(reason, entry.label)
            self.assertTrue(entry.label.startswith(f"{group.kind}: условий {group.condition_count} "))
            self.assertIn(f"Часть: {group.part}; индекс правила Xray: {group.index} (счёт с нуля)", entry.card)
        self.assertIn("условий", text)

    def test_manager_metadata_present_and_absent(self):
        with forbid_external_effects():
            present = present_manager_metadata(self.results["metadata"].data)
            absent = present_manager_metadata(self.results["no_metadata"].data)
        text = self.assert_safe_lines(present)
        self.assertIn("Версия схемы: 1; неизвестных полей: 0", text)
        self.assertIn("Вариант хранения: known simple; различных хранилищ: 1", text)
        roles = self.results["metadata"].data.metadata.storage.roles
        self.assertEqual(len([line for line in present if line.startswith("  Роль ")]), len(roles))
        for role in roles:
            self.assertIn(f"Роль {role.role}: состояние known, идентификатор known, путь known, проверено да", text)
        self.assertIn(
            f"История: размер known {SYNTHETIC_HISTORY_SIZE} байт; срок known {SYNTHETIC_HISTORY_RETENTION} с", text,
        )
        self.assertEqual(absent, ["Метаданные менеджера", "Метаданных нет: размещение хранилищ ещё не записано."])

    def test_checks_presenter_shows_catalog_labels_and_never_derives_status(self):
        view = ChecksView(False, (
            CheckView(XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, "process_without_marker"),
            CheckView("geodata_references_resolved", CheckStatus.UNSUPPORTED, False, "files_not_inventoried"),
            CheckView(VPN_REACHABLE_CHECK, CheckStatus.NOT_CHECKED, True, "network_check_not_performed"),
        ))
        with forbid_external_effects():
            lines = present_checks(view)
        self.assert_safe_lines(lines)
        self.assertEqual(lines, [
            "Проверки",
            "Активная сетевая проверка: не выполнялась",
            "  xray_process_consistent: ошибка, причина process_without_marker",
            "  geodata_references_resolved: не поддерживается, причина files_not_inventoried",
            "  vpn_reachable: не проверено, причина network_check_not_performed (сетевая проверка)",
        ])
        active = ChecksView(True, (CheckView(VPN_REACHABLE_CHECK, CheckStatus.PASSED, True, None),))
        self.assertEqual(present_checks(active)[1:], ["Активная сетевая проверка: выполнялась", "  vpn_reachable: успешно (сетевая проверка)"])
        for status in CheckStatus:
            self.assertEqual(check_status(status), CHECK_STATUS_LABELS[status])
        # Статус показывается только из словаря контракта: строка, другое перечисление и код ошибки скрываются.
        for value in ("passed", "failed", "source_failed", None, 1, _OddCode.BAD):
            with self.subTest(value=value):
                self.assertEqual(check_status(value), HIDDEN)
        with self.assertRaises(TypeError):
            present_checks(view.items)
        with self.assertRaises(TypeError):
            present_checks({"active_network_check": False, "items": []})

    def test_geodata_and_process_presenters_accept_only_their_views(self):
        view = self.results["installation"].data
        with forbid_external_effects():
            geodata = present_geodata(view.geodata)
            process = present_xray_process(view.xray_process)
        self.assert_safe_lines(geodata)
        self.assert_safe_lines(process)
        self.assertIn("Ссылок правил и DNS на наборы: 1; сопоставлено 1; не сопоставлено 0; неподдержанных 0", geodata)
        for present, wrong in (
            (present_installation, view.keenetic), (present_keenetic_state, view.proxy),
            (present_proxy_summary, view.keenetic), (present_port53, view.geodata),
            (present_geodata, view.xray_process), (present_xray_process, view.geodata),
            (present_routing_scheme, view), (present_manager_metadata, view),
        ):
            with self.subTest(presenter=present.__name__), self.assertRaises(TypeError):
                present(wrong)

    def test_result_presenter_uses_data_or_error(self):
        installation = self.results["installation"]
        with forbid_external_effects():
            success = present_result(installation, present_installation)
            failure = present_result(
                failed("op", "inspect_installation", ErrorDetail(
                    ErrorCategory.SOURCE_FAILED, "xray_config_unavailable", "Не удалось прочитать части.",
                    reason="io_error",
                )),
                present_installation,
            )
        self.assertEqual(success[0], "Сводка установки по прочитанным источникам")
        self.assertEqual(failure, [
            "Отказ: source_failed / xray_config_unavailable", "Уточнение: io_error",
            "Причина: Не удалось прочитать части.",
            f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}",
        ])
        with self.assertRaises(TypeError):
            present_result(installation.to_dict(), present_installation)

    def test_about_mentions_mark_and_contract_version(self):
        with forbid_external_effects():
            lines = present_about()
        text = self.assert_safe_lines(lines)
        self.assertEqual(lines[0], "Справка по меню KeenVPN")
        self.assertIn(UNAVAILABLE_MARK, text)
        self.assertIn(f"Версия контракта результатов прикладных сценариев: {CONTRACT_VERSION}", lines[-1])
        self.assertIn("0 возвращает на уровень выше", text)


class KnownValueTests(PresenterAssertions):
    """Регрессия review 71-R03: известное, но скрытое значение не выдаётся за отсутствующее."""

    def test_known_value_branches(self):
        self.assertEqual(known_value(False, None, identifier, "без тега"), "без тега")
        self.assertEqual(known_value(True, None, identifier, "без тега"), HIDDEN)
        self.assertEqual(known_value(True, "trojan-out", identifier, "без тега"), "trojan-out")
        self.assertEqual(known_value(True, "probe.example", identifier, "без тега"), HIDDEN)
        for known in (None, 1, "true"):
            self.assertEqual(known_value(known, "trojan-out", identifier, "без тега"), HIDDEN)

    def test_rule_target_tag_known_hidden_and_absent(self):
        view = self.results["routing"].data
        group = next(item for item in view.groups if item.target.tag is not None)
        hidden = replace(group, target=replace(group.target, tag_known=True, tag=None))
        absent = replace(group, target=replace(group.target, tag_known=False, tag=None))
        lines = {
            name: present_routing_scheme(replace(view, groups=(item,))).entries[-1].label
            for name, item in (("shown", group), ("hidden", hidden), ("absent", absent))
        }
        self.assertIn(f"назначение {group.target.kind} {group.target.tag},", lines["shown"])
        self.assertIn(f"назначение {group.target.kind} {HIDDEN},", lines["hidden"])
        self.assertIn(f"назначение {group.target.kind} без тега,", lines["absent"])
        for line in lines.values():
            self.assertNotIn(MISSING, line)

    def test_geo_source_and_version_known_hidden_and_absent(self):
        geodata = self.results["installation"].data.geodata
        base = geodata.files[0]
        self.assertIs(type(base), GeoDatabaseFileView)
        cases = {
            "hidden": replace(base, source_known=True, source=None, version_known=True, version=None),
            "absent": replace(base, source_known=False, source=None, version_known=False, version=None),
            "shown": replace(base, source_known=True, source="fixture-geo-source", version_known=True, version="test-v1"),
        }
        lines = {name: present_geodata(replace(geodata, files=(item,)))[2] for name, item in cases.items()}
        self.assertIn(f"источник {HIDDEN}, версия {HIDDEN}", lines["hidden"])
        self.assertIn("источник неизвестен, версия неизвестна", lines["absent"])
        self.assertIn("источник fixture-geo-source, версия test-v1", lines["shown"])
        for line in lines.values():
            self.assertNotIn("источник нет данных", line)
            self.assertNotIn("версия нет данных", line)


class RoutingCardTests(PresenterAssertions):
    """Карточка группы правил: те же фильтры, что у строки списка, и различие скрытого и отсутствующего."""

    def card(self, **changes) -> tuple[str, ...]:
        view = self.results["routing"].data
        group = next(item for item in view.groups if item.target.kind == "balancer")
        target_changes = {key[7:]: value for key, value in changes.items() if key.startswith("target_")}
        group_changes = {key: value for key, value in changes.items() if not key.startswith("target_")}
        group = replace(group, target=replace(group.target, **target_changes), **group_changes)
        with forbid_external_effects():
            return present_routing_scheme(replace(view, groups=(group,))).entries[0].card

    def test_card_on_snapshot_is_safe_and_names_every_area(self):
        view = self.results["routing"].data
        with forbid_external_effects():
            groups = present_routing_scheme(view)
        text = self.assert_safe_lines([line for entry in groups.entries for line in entry.card])
        for label in ("Часть: ", "Вид: ", "Условий: ", "Причины значений: ", "Поля правила: ", "Тег правила: ",
                      "Действие: ", "Назначение: ", "Outbound назначения: ", "Причины назначения: "):
            self.assertEqual(text.count(label), len(view.groups), label)
        self.assertIn("сами значения не показываются", text)

    def test_target_tags_fallback_and_strategy_are_filtered(self):
        shown = self.card()
        self.assertIn("Назначение: balancer vpn-group; запасной: blocked; стратегия: leastPing; действие назначения: нет",
                      shown)
        self.assertIn("Outbound назначения: 1", shown)
        self.assertIn("  trojan-out", shown)
        hidden = self.card(
            target_outbound_tags=(None, "probe.example", "trojan-out"), target_fallback_known=True,
            target_fallback_tag=None, target_strategy_known=True, target_strategy=None,
        )
        self.assertIn(f"  {HIDDEN}, {HIDDEN}, trojan-out", hidden)
        self.assertIn(f"запасной: {HIDDEN}; стратегия: {HIDDEN}", "\n".join(hidden))
        self.assertNotIn("probe.example", "\n".join(hidden))
        absent = "\n".join(self.card(
            target_fallback_known=False, target_fallback_tag=None, target_strategy_known=False, target_strategy=None,
        ))
        self.assertIn("запасной: не задан; стратегия: не задана", absent)

    def test_many_outbound_tags_are_split_into_lines_within_the_limit(self):
        # Регрессия review 72-R01: число outbound задаёт конфигурация, строка карточки не превышает предел.
        tags = tuple(f"out-{number:02d}-" + "a" * 53 for number in range(40)) + ("probe.example",)
        card = self.card(target_outbound_tags=tags)
        self.assertTrue(all(len(line) <= MAX_LIST_LINE_LENGTH for line in card))
        self.assertIn("Outbound назначения: 41", card)
        tag_lines = [line for line in card if line.startswith("  ")]
        self.assertEqual(len(tag_lines), 5)
        self.assertEqual([len(line[2:].split(", ")) for line in tag_lines], [10, 10, 10, 10, 1])
        self.assertEqual(", ".join(line[2:] for line in tag_lines), ", ".join((*tags[:-1], HIDDEN)))
        empty = self.card(target_outbound_tags=())
        self.assertIn("Outbound назначения: 0", empty)
        self.assertFalse([line for line in empty if line.startswith("  ")])

    def test_rule_tag_presence_without_value_and_field_names_filter(self):
        self.assertIn("Тег правила: задан, значение не показывается", self.card(has_rule_tag=True))
        self.assertIn("Тег правила: не задан", self.card(has_rule_tag=False))
        self.assertIn(f"Тег правила: {HIDDEN}", self.card(has_rule_tag=None))
        card = "\n".join(self.card(fields=("domain", "probe.example", "a b"), unsupported_fields=("attrs", "x/y")))
        self.assertIn(f"Поля правила: domain, {HIDDEN}, {HIDDEN}; неподдержанные: attrs, {HIDDEN}", card)
        self.assertIn(f"Часть: {HIDDEN}", self.card(part="../05_routing.json")[0])

    def test_more_groups_than_numbers_are_cut_with_a_note(self):
        view = self.results["routing"].data
        many = replace(view, groups=view.groups[:1] * (MAX_ITEM_NUMBER + 1))
        with forbid_external_effects():
            groups = present_routing_scheme(many)
        self.assertEqual(len(groups.entries), MAX_ITEM_NUMBER)
        self.assertEqual(groups.entries[-1].number, MAX_ITEM_NUMBER)
        self.assertIn(f"Групп больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.",
                      groups.header)


NAME_MARKER = "TEST_ONLY_PRIVATE_NAME"
RULE_ID = "0000abcd-0000-4000-8000-ffff00000001"


def fixed_id(index: int) -> str:
    return f"0000abcd-0000-4000-8000-ffff{index:08x}"


class ConnectionsPresenterTests(PresenterAssertions):
    """Список подключений: строки и карточки из тех же отфильтрованных значений, скрытое отличается от отсутствующего."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        sources = snapshot_installation_sources()
        proxy = InspectProxyConfigHandler(sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists)
        result = InspectConnectionsHandler(proxy).execute(InspectConnections())
        assert result.succeeded
        cls.connections = result.data

    def test_snapshot_list_has_outbounds_then_balancer_with_positions(self):
        with forbid_external_effects():
            listing = present_connections(self.connections)
        self.assertIs(type(listing), MenuList)
        self.assertEqual((listing.title, listing.item_name), (CONNECTIONS_LIST_TITLE, CONNECTIONS_ITEM_NAME))
        text = self.assert_safe_lines(list_lines(listing))
        self.assertEqual(listing.header[0], "Подключения по конфигурации Xray")
        self.assertIn("Частей: 7; outbound: 3; балансировщиков: 1", text)
        self.assertIn("Повторов тегов outbound: 0; повторов тегов балансировщиков: 0; скрытых тегов: 0", text)
        self.assertIn(CONNECTIONS_NOTE, listing.header)
        self.assertIn(CONNECTIONS_HEALTH_NOTE, listing.header)
        self.assertEqual([entry.number for entry in listing.entries], [1, 2, 3, 4])
        self.assertEqual(listing.entries[0].label, "outbound: тег trojan-out, протокол trojan, часть 04_outbounds.json, индекс 0")
        self.assertEqual(
            listing.entries[3].label,
            "балансировщик: тег vpn-group, селекторов 1, совпадений 1, fallback blocked, стратегия leastPing, "
            "часть 05_routing.json, индекс 0",
        )
        self.assertEqual(listing.entries[1].card, (
            "Вид: outbound", "Позиция: часть 04_outbounds.json, индекс 1", "Тег: direct", "Протокол: freedom",
            CONNECTIONS_NOTE,
        ))
        self.assertEqual(listing.entries[3].card, (
            "Вид: балансировщик", "Позиция: часть 05_routing.json, индекс 0", "Тег: vpn-group",
            "Селекторов: 1; совпадений outbound: 1", "  trojan-out",
            "Fallback: blocked; позиция цели: часть 04_outbounds.json, индекс 2", "Стратегия: leastPing",
            CONNECTIONS_NOTE,
        ))
        with self.assertRaises(TypeError):
            present_connections(self.connections.connections)

    def test_hidden_and_absent_values_are_distinguished_and_positions_tell_hidden_apart(self):
        position = XrayPositionView("04_outbounds.json", 5)
        hidden = OutboundConnectionView(position, True, None, True, None)
        other = OutboundConnectionView(XrayPositionView("04_outbounds.json", 6), True, None, True, None)
        absent = OutboundConnectionView(XrayPositionView("tail_outbounds.json", 0), False, None, False, None)
        shown = OutboundConnectionView(XrayPositionView("../x.json", 0), True, "probe.example", True, "trojan")
        view = ConnectionsView(2, 4, 0, 0, 0, 2, (hidden, other, absent, shown))
        with forbid_external_effects():
            listing = present_connections(view)
        labels = [entry.label for entry in listing.entries]
        self.assertEqual(labels[0], f"outbound: тег {HIDDEN}, протокол {HIDDEN}, часть 04_outbounds.json, индекс 5")
        self.assertEqual(labels[1], f"outbound: тег {HIDDEN}, протокол {HIDDEN}, часть 04_outbounds.json, индекс 6")
        self.assertNotEqual(labels[0], labels[1])
        self.assertEqual(labels[2], "outbound: тег без тега, протокол не задан, часть tail_outbounds.json, индекс 0")
        # Тег в форме домена и имя части с каталогом не проходят фильтры даже если application их пропустил бы.
        self.assertEqual(labels[3], f"outbound: тег {HIDDEN}, протокол trojan, часть {HIDDEN}, индекс 0")
        self.assertNotIn("probe.example", "\n".join(list_lines(listing)))
        self.assertIn("скрытых тегов: 2", listing.header[2])
        self.assertNotIn(MISSING, "\n".join(labels))

    def test_balancer_card_splits_selectors_and_names_fallback_states(self):
        def balancer(**changes):
            values = {
                "position": XrayPositionView("05_routing.json", 0), "tag_known": True, "tag": "pool",
                "selector": tuple(f"sel-{number:02d}-" + "a" * 50 for number in range(21)) + ("", None, "probe.example"),
                "selector_match_count": 7, "fallback_known": True, "fallback_tag": "direct", "fallback_resolved": True,
                "fallback_position": XrayPositionView("04_outbounds.json", 1), "strategy_known": True,
                "strategy": "leastPing",
            }
            values.update(changes)
            return BalancerConnectionView(**values)

        def card(**changes):
            item = balancer(**changes)
            view = ConnectionsView(1, 0, 1, 0, 0, int(item.tag_known and item.tag is None), (item,))
            with forbid_external_effects():
                return present_connections(view).entries[0].card

        shown = card()
        self.assertIn("Селекторов: 24; совпадений outbound: 7", shown)
        selector_lines = [line for line in shown if line.startswith("  ")]
        self.assertEqual([len(line[2:].split(", ")) for line in selector_lines], [10, 10, 4])
        self.assertTrue(all(len(line) <= MAX_LIST_LINE_LENGTH for line in shown))
        self.assertTrue(selector_lines[2].endswith(f", пустой, {HIDDEN}, {HIDDEN}"))
        self.assertIn("Fallback: direct; позиция цели: часть 04_outbounds.json, индекс 1", shown)
        self.assertIn("Стратегия: leastPing", shown)
        self.assertNotIn("probe.example", "\n".join(shown))
        self.assertIn(
            "Fallback: не задан; позиция цели: не задан",
            card(fallback_known=False, fallback_tag=None, fallback_resolved=None, fallback_position=None),
        )
        self.assertIn("Fallback: missing; позиция цели: не найден", card(fallback_tag="missing", fallback_resolved=False, fallback_position=None))
        self.assertIn(f"Fallback: {HIDDEN}; позиция цели: не определена однозначно", card(fallback_tag=None, fallback_position=None))
        self.assertIn(f"Стратегия: {HIDDEN}", card(strategy=None))
        self.assertIn("Стратегия: не задана", card(strategy_known=False, strategy=None))
        self.assertIn(f"Тег: {HIDDEN}", card(tag=None))
        self.assertEqual(card(selector=())[3:5], ("Селекторов: 0; совпадений outbound: 7", "Fallback: direct; позиция цели: часть 04_outbounds.json, индекс 1"))

    def test_more_connections_than_numbers_are_cut_with_a_note(self):
        item = self.connections.connections[0]
        many = ConnectionsView(1, MAX_ITEM_NUMBER + 1, 0, 0, 0, 0, (item,) * (MAX_ITEM_NUMBER + 1))
        with forbid_external_effects():
            listing = present_connections(many)
        self.assertEqual(len(listing.entries), MAX_ITEM_NUMBER)
        self.assertIn(f"Подключений больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.",
                      listing.header)


class RuleListPresenterTests(PresenterAssertions):
    """Список правил: строки и карточки групп с названиями и идентификаторами из метаданных."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        sources = snapshot_installation_sources()
        proxy = InspectProxyConfigHandler(sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists)
        cls.routing = ImportRoutingSchemeHandler(proxy)
        rules = scheme_rules(import_routing_scheme(snapshot_xray_config()))
        records = tuple(RuleRecord(fixed_id(number), None, rule_key(rule)) for number, rule in enumerate(rules))
        records = (
            RuleRecord(fixed_id(0), NAME_MARKER, records[0].key), RuleRecord(fixed_id(1), "Рабочий сервис напрямую", records[1].key),
            *records[2:],
        )
        store = InMemoryManagerMetadataStore(encode_manager_metadata(ManagerMetadata(None, UnknownFields(), rules=records)))
        cls.present = ListRoutingRulesHandler(cls.routing, store).execute(ListRoutingRules()).data
        cls.absent = ListRoutingRulesHandler(cls.routing, InMemoryManagerMetadataStore()).execute(ListRoutingRules()).data
        cls.not_connected = ListRoutingRulesHandler(cls.routing, None).execute(ListRoutingRules()).data
        failing = InMemoryManagerMetadataStore()
        failing.read_failure = ManagerMetadataStoreError(MetadataStoreFailure.BUSY)
        cls.failed = ListRoutingRulesHandler(cls.routing, failing).execute(ListRoutingRules()).data

    def listing(self, view):
        with forbid_external_effects():
            return present_rule_list(view)

    def test_present_metadata_adds_counts_names_and_rule_lines_to_groups(self):
        listing = self.listing(self.present)
        base = present_routing_scheme(self.present.scheme)
        self.assertEqual((listing.title, listing.item_name), (ROUTING_LIST_TITLE, ROUTING_ITEM_NAME))
        self.assertEqual(listing.header[:len(base.header)], base.header)
        self.assertIn(METADATA_NOTES[MetadataState.PRESENT], listing.header)
        self.assertIn("Идентичность: записей правил 40; привязано 40, с названием 2, без привязки 0; записей без правила 0", listing.header)
        text = "\n".join(list_lines(listing))
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertTrue(all(line.isprintable() for line in text.splitlines()))
        self.assertEqual([entry.number for entry in listing.entries], list(range(1, 9)))
        first, second = listing.entries[0], listing.entries[1]
        self.assertEqual(first.label, base.entries[0].label + f", правил 1, с ID 1, с названием 1, названия: «{NAME_MARKER}»")
        self.assertEqual(second.label, base.entries[1].label + ", правил 3, с ID 3, с названием 1, названия: «Рабочий сервис напрямую»")
        self.assertEqual(listing.entries[2].label, base.entries[2].label + ", правил 0, с ID 0, с названием 0")
        self.assertEqual(first.card[:len(base.entries[0].card)], base.entries[0].card)
        self.assertEqual(first.card[len(base.entries[0].card):], (
            "Назначение по позиции: часть 04_outbounds.json, индекс 1",
            "Правил модели: 1 (позиция в схеме, счёт с нуля)",
            f"  0: UnsupportedRuleCondition, действие DIRECT, только просмотр да, ID {fixed_id(0)}, "
            f"название «{NAME_MARKER}», привязка bound",
        ))
        self.assertIn(
            f"  1: DomainCondition, действие DIRECT, только просмотр нет, ID {fixed_id(1)}, "
            "название «Рабочий сервис напрямую», привязка bound", second.card,
        )
        self.assertIn(f"  2: DomainCondition, действие DIRECT, только просмотр нет, ID {fixed_id(2)}, название не задано, привязка bound", second.card)
        self.assertIn("Назначение по позиции: часть 05_routing.json, индекс 0", listing.entries[2].card)
        with self.assertRaises(TypeError):
            present_rule_list(self.present.scheme)

    def test_absent_not_connected_and_failed_metadata_keep_the_list(self):
        absent = self.listing(self.absent)
        self.assertIn(METADATA_NOTES[MetadataState.ABSENT], absent.header)
        self.assertIn("Идентичность: раздел записей не записан; привязано 0, с названием 0, без привязки 40; записей без правила 0", absent.header)
        self.assertTrue(absent.entries[0].label.endswith(", правил 1, с ID 0, с названием 0"))
        self.assertIn("  0: UnsupportedRuleCondition, действие DIRECT, только просмотр да, ID не присвоен, название не задано, привязка record_missing", absent.entries[0].card)
        not_connected = self.listing(self.not_connected)
        self.assertIn(METADATA_NOTES[MetadataState.NOT_CONNECTED], not_connected.header)
        self.assertNotIn("Идентичность:", "\n".join(not_connected.header))
        self.assertTrue(not_connected.entries[0].label.endswith(", правил 1"))
        self.assertNotIn("с ID", not_connected.entries[0].label)
        self.assertIn("Правил модели: 1; названия и идентификаторы недоступны", not_connected.entries[0].card)
        self.assertFalse([line for line in not_connected.entries[1].card if "привязка" in line])
        failed = self.listing(self.failed)
        self.assertIn(METADATA_NOTES[MetadataState.FAILED], failed.header)
        self.assertIn("  Отказ: source_failed / metadata_store_busy", failed.header)
        self.assertIn(f"  Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.RETRY_LATER]}", failed.header)
        self.assertEqual(len(failed.entries), 8)
        self.assertIn("Правил модели: 3; названия и идентификаторы недоступны", failed.entries[1].card)

    def test_names_pass_only_the_filter_and_label_stays_within_the_limit(self):
        for value in ("Рабочий сервис", "a", "x" * 64, "name with spaces", "«кавычки»", "1"):
            with self.subTest(value=value):
                self.assertEqual(rule_name(value), value)
        for value in ("", " x", "x ", "x" * 65, "a\x1bb", "a\nb", "a\tb", "\u200bx", None, 5, b"x", "\ud800"):
            with self.subTest(value=repr(value)):
                self.assertEqual(rule_name(value), HIDDEN)
        self.assertEqual(rule_id(RULE_ID), RULE_ID)
        for value in (RULE_ID.upper(), RULE_ID.replace("-", ""), "x", None, RULE_ID + "x"):
            with self.subTest(value=value):
                self.assertEqual(rule_id(value), HIDDEN)
        view = self.present
        group = view.groups[5]
        long_name = "н" * 64
        rules = tuple(
            replace(item, has_name=True, name=long_name) for item in group.rules
        )
        changed = replace(view, groups=(*view.groups[:5], replace(group, rules=rules), *view.groups[6:]))
        listing = self.listing(changed)
        label = listing.entries[5].label
        self.assertLessEqual(len(label), MAX_LIST_LINE_LENGTH)
        self.assertIn(f", с ID 19, с названием 19, названия: " + ", ".join([f"«{long_name}»"] * NAMES_PER_LABEL) + " (ещё 9)", label)
        self.assertEqual(sum(line.count(long_name) for line in listing.entries[5].card), 19)

    def test_entry_values_outside_formats_are_hidden_in_lines(self):
        view = self.present
        group = view.groups[0]
        odd = RuleListEntryView(0, 0, "DomainCondition", "DIRECT", False, True, fixed_id(9), True, "ok", "bound")
        changed = replace(view, groups=(replace(group, rules=(odd,)), *view.groups[1:]))
        card = self.listing(changed).entries[0].card
        self.assertIn(f"  0: DomainCondition, действие DIRECT, только просмотр нет, ID {fixed_id(9)}, название «ok», привязка bound", card)
        for state, label in TARGET_POSITION_LABELS.items():
            with self.subTest(state=state.value):
                group_state = replace(group, target_position_state=state, target_position=None)
                listing = self.listing(replace(view, groups=(group_state, *view.groups[1:])))
                self.assertIn(f"Назначение по позиции: {label}", listing.entries[0].card)

    def test_label_tables_are_read_only(self):
        # Регрессия приёмки блока сводки: таблицы подписей списка правил только для чтения, как каталоги application.
        for table, key in ((METADATA_NOTES, MetadataState.PRESENT), (TARGET_POSITION_LABELS, TargetPositionState.ABSENT)):
            with self.subTest(key=key.value):
                with self.assertRaises(TypeError):
                    table[key] = "другой текст"
                with self.assertRaises(TypeError):
                    del table[key]
        self.assertEqual(set(METADATA_NOTES), set(MetadataState))
        self.assertEqual(set(TARGET_POSITION_LABELS), set(TargetPositionState) - {TargetPositionState.RESOLVED})


class RoutingReasonTests(unittest.TestCase):
    """Регрессия review 71-R04: причины назначения и значений видны рядом с правилом."""

    def routing_groups(self, files=None) -> dict[int, str]:
        sources = snapshot_installation_sources()
        if files is not None:
            sources.proxy.xray.outcome = xray_config_from_files(files)
        proxy = InspectProxyConfigHandler(
            sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists,
        )
        result = ImportRoutingSchemeHandler(proxy).execute(ImportRoutingScheme())
        self.assertTrue(result.succeeded)
        with forbid_external_effects():
            groups = present_routing_scheme(result.data)
        self.text = "\n".join(list_lines(groups))
        return {entry.number: entry.label for entry in groups.entries}

    def test_balancer_fallback_reason_is_shown_for_each_affected_rule(self):
        groups = self.routing_groups()
        for number in (3, 4, 8):
            with self.subTest(number=number):
                self.assertIn("причины назначения: fallback_mixed", groups[number])
                self.assertIn("только просмотр да", groups[number])
        self.assertNotIn("причины назначения", groups[2])

    def test_value_reasons_are_codes_with_counts_without_values_or_paths(self):
        files = load_xray_snapshot_files()
        routing = json.loads(files["05_routing.json"])
        rule = routing["routing"]["rules"][1]
        rule["domain"] = ["regexp:^TEST_ONLY_VALUE[.]example$", "regexp:^second[.]example$", *rule["domain"]]
        files["05_routing.json"] = json.dumps(routing).encode("utf-8")
        group = self.routing_groups(files)[2]
        text = self.text
        self.assertIn("причины значений: domain_regexp ×2", group)
        self.assertIn("только просмотр да", group)
        self.assertIn("Причины значений: domain_regexp ×2", text)
        for private in ("TEST_ONLY_VALUE", "regexp:", "second", "routing.rules", "domain[0]"):
            self.assertNotIn(private, text)


class SafeValueTests(unittest.TestCase):
    def test_identifier_accepts_technical_ids_and_hides_everything_else(self):
        for value in ("Policy10", "trojan-out", "a" * 64, "running", "dns-local", "IPOnDemand", "fallback_mixed",
                      "vless+reality", "1181"):
            with self.subTest(value=value):
                self.assertEqual(identifier(value), value)
        for value in ("", "a" * 65, "../etc", ".hidden", "-x", "a b", "тег", "a\x1bb", "pass@host", "a=b", 5, None,
                      b"tag", "x\n", "dns.tag", "GigabitEthernet0/Vlan1", "05_routing.json"):
            with self.subTest(value=value):
                self.assertEqual(identifier(value), HIDDEN)

    def test_tag_rule_hides_domains_addresses_macs_and_urls(self):
        # Значения из замечания review 71-R01: тег задаёт пользователь, поэтому их форма не выводится.
        for value in ("probe.example", "192.0.2.10", "2001:db8::10", "02:00:00:54:00:01",
                      "https://example.invalid/TEST_ONLY_TOKEN", "example.invalid/TEST_ONLY_TOKEN", "user@probe.example"):
            with self.subTest(value=value):
                self.assertEqual(identifier(value), HIDDEN)
                self.assertEqual(identifiers((value, "dns-local")), f"{HIDDEN}, dns-local")

    def test_kind_specific_rules(self):
        self.assertEqual(file_name("05_routing.json"), "05_routing.json")
        self.assertEqual(file_name("geoip.dat"), "geoip.dat")
        for value in ("probe.example", "../05_routing.json", "dir/05_routing.json", "05_routing.json.bak", ".json",
                      "a" * 60 + ".json", "geoip.dat:1", None):
            with self.subTest(file=value):
                self.assertEqual(file_name(value), HIDDEN)
        self.assertEqual((optional_file_name(None), optional_file_name("geosite.dat")), (MISSING, "geosite.dat"))
        for value in ("Bridge0", "GigabitEthernet0/Vlan1", "GigabitEthernet0/0.1", "Wireguard0"):
            with self.subTest(interface=value):
                self.assertEqual(interface_id(value), value)
        for value in ("02:00:00:54:00:01", "192.0.2.10", "2001:db8::10", "https://example.invalid/x", "0Bridge",
                      "Bridge0/", "Bridge0//1", "a b", "I" * 65, None):
            with self.subTest(interface=value):
                self.assertEqual(interface_id(value), HIDDEN)
        self.assertEqual(digest("3f" * 32), "3f" * 32)
        for value in ("3F" * 32, "3f" * 31, "3f" * 33, "g" * 64, None):
            with self.subTest(digest=value):
                self.assertEqual(digest(value), HIDDEN)
        self.assertEqual((optional_digest(None), optional_digest("0" * 64)), (MISSING, "0" * 64))
        for value in ("fixture-geo-source", "v2fly.domain-list", "https://github.example", "http://mirror.example:8080"):
            with self.subTest(source=value):
                self.assertEqual(geo_source(value), value)
        for value in ("https://user:pass@mirror.example", "https://mirror.example/path?token=x", "/opt/share/geo",
                      "ftp://mirror.example", "a b", None):
            with self.subTest(source=value):
                self.assertEqual(geo_source(value), HIDDEN)
        for value in ("202610160000", "v1.2.3", "test-v1"):
            with self.subTest(version=value):
                self.assertEqual(geo_version(value), value)
        for value in ("v1/2", "1:2", "a b", "x" * 65, None):
            with self.subTest(version=value):
                self.assertEqual(geo_version(value), HIDDEN)
        self.assertEqual(optional_identifier(None), MISSING)
        self.assertEqual(optional_identifier("Policy10"), "Policy10")
        self.assertEqual(identifiers(()), "нет")
        self.assertEqual(identifiers(("a", "b c")), f"a, {HIDDEN}")

    def test_flags_counts_and_text(self):
        self.assertEqual((flag(True), flag(False)), ("да", "нет"))
        for value in (1, 0, "да", None):
            self.assertEqual(flag(value), HIDDEN)
        self.assertEqual(optional_flag(None), MISSING)
        self.assertEqual((count(0), count(42)), ("0", "42"))
        for value in (True, False, 1.5, "7", None):
            self.assertEqual(count(value), HIDDEN)
        self.assertEqual(optional_count(None), MISSING)
        self.assertEqual(safe_text("Текст причины."), "Текст причины.")
        for value in ("", "a\x1b[0m", "строка\nещё", "x" * (presenters.MAX_TEXT_LENGTH + 1), 7):
            self.assertEqual(safe_text(value), HIDDEN)

    def test_error_presenter_hides_malformed_codes_and_texts(self):
        error = ErrorDetail(ErrorCategory.INVALID_SOURCE_DATA, "bad code!", "Текст\x1b[31m", reason="..")
        # Код и текст вне формата скрываются, а шаг категории из каталога остаётся: его текст задан заранее.
        self.assertEqual(present_error(error), [
            f"Отказ: invalid_source_data / {HIDDEN}", f"Уточнение: {HIDDEN}", f"Причина: {HIDDEN}",
            f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.INSPECT_SOURCE_DATA]}",
        ])
        plain = ErrorDetail(ErrorCategory.UNSUPPORTED, "storage_placement_mismatch", "Текст.")
        self.assertEqual(present_error(plain), [
            "Отказ: unsupported / storage_placement_mismatch", "Причина: Текст.",
            f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.OPEN_VIEW]}",
        ])
        with self.assertRaises(TypeError):
            present_error({"code": "x"})

    def test_error_presenter_shows_step_only_when_application_gives_one(self):
        # Шаг берётся из ErrorDetail как есть: без шага строки нет, меню его не вычисляет.
        without_step = ErrorDetail(ErrorCategory.INVALID_REQUEST, "invalid_command", "Команда сформирована некорректно.")
        self.assertEqual(present_error(without_step), [
            "Отказ: invalid_request / invalid_command", "Причина: Команда сформирована некорректно.",
        ])
        for category, code, step in (
            (ErrorCategory.INVALID_INPUT, "invalid_domain", NextStepCode.RETRY_INPUT),
            (ErrorCategory.SOURCE_FAILED, "metadata_store_busy", NextStepCode.RETRY_LATER),
            (ErrorCategory.INVALID_SOURCE_DATA, "invalid_stored_metadata", NextStepCode.PRESERVE_FILE),
            (ErrorCategory.INVALID_REQUEST, "unsupported_contract_version", NextStepCode.UPDATE_INTERFACE),
        ):
            with self.subTest(code=code):
                lines = present_error(ErrorDetail(category, code, "Текст."))
                self.assertEqual(len(lines), 3)
                self.assertEqual(lines[-1], f"Следующий шаг: {NEXT_STEP_MESSAGES[step]}")
                self.assertTrue(lines[-1].isprintable())
                self.assertLessEqual(len(NEXT_STEP_MESSAGES[step]), presenters.MAX_TEXT_LENGTH)
        # Регрессия review 227-R01: код-перечисление допустим в ErrorDetail и не должен ронять показ отказа.
        enum_coded = ErrorDetail(ErrorCategory.INVALID_REQUEST, ErrorCode.UNSUPPORTED_CONTRACT_VERSION, "Текст.")
        self.assertEqual(present_error(enum_coded)[-1], f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.UPDATE_INTERFACE]}")
        self.assertEqual(len(present_error(ErrorDetail(ErrorCategory.INVALID_REQUEST, ErrorCode.INVALID_COMMAND, "Текст."))), 2)

    def test_error_presenter_shows_enum_codes_and_reasons_by_value(self):
        # Контракт принимает в коде и уточнении подклассы str: показывается значение, а не пометка скрытого.
        error = ErrorDetail(
            ErrorCategory.SOURCE_FAILED, MetadataStoreFailure.BUSY, "Текст.", reason=MetadataStoreFailure.BUSY,
        )
        self.assertEqual(present_error(error), [
            "Отказ: source_failed / metadata_store_busy", "Уточнение: metadata_store_busy", "Причина: Текст.",
            f"Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.RETRY_LATER]}",
        ])
        self.assertEqual(
            present_error(ErrorDetail(ErrorCategory.INVALID_REQUEST, ErrorCode.INVALID_COMMAND, "Текст."))[0],
            "Отказ: invalid_request / invalid_command",
        )
        # Фильтр формата действует и на значение перечисления.
        self.assertEqual(present_error(ErrorDetail(ErrorCategory.INVALID_INPUT, _OddCode.BAD, "Текст."))[0], f"Отказ: invalid_input / {HIDDEN}")
        # Успешный результат любого сценария отдаётся переданному представлению как есть.
        data = _Data()
        self.assertEqual(present_result(succeeded("op", "cmd", data), lambda view: [repr(view is data)]), ["True"])


class _Data:
    def to_dict(self):
        return {}


SUMMARY_HEADER = [
    "Состояние по источникам, активная сетевая проверка не выполнялась:",
    "  Ядро Xray: работает",
    "  Перехват: не поддерживается",
    "  Доступность VPN: не проверено",
    "  DNS и порт 53: исключение 53 включено, не проверено",
    "  Автозапуск: включён",
    "  Режим резерва: без прямого резерва",
    "  Черновик: не поддерживается",
]


def summary_view(sources=None, *, connected=True):
    sources = snapshot_installation_sources() if sources is None else sources
    proxy = None
    if connected:
        proxy = InspectProxyConfigHandler(sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists)
    result = InspectStatusSummaryHandler(proxy, sources.process if connected else None).execute(InspectStatusSummary())
    assert result.succeeded
    return result.data


class StatusSummaryPresenterTests(PresenterAssertions):
    def test_header_shows_each_area_on_its_own_line_from_catalogs(self):
        view = summary_view()
        with forbid_external_effects():
            lines = present_status_header(view)
        self.assert_safe_lines(lines)
        self.assertEqual(lines, SUMMARY_HEADER)
        # Без источников ни одна область не выглядит исправной: состояние не известно, статус — «не проверено».
        self.assertEqual(present_status_header(summary_view(connected=False))[1:], [
            "  Ядро Xray: не проверено", "  Перехват: не поддерживается", "  Доступность VPN: не проверено",
            "  DNS и порт 53: не проверено", "  Автозапуск: не проверено", "  Режим резерва: не проверено",
            "  Черновик: не поддерживается",
        ])

    def test_summary_shows_checks_facts_hint_and_disclaimer(self):
        view = summary_view()
        with forbid_external_effects():
            lines = present_status_summary(view)
        self.assert_safe_lines(lines)
        self.assertEqual(lines, [
            "Сводка состояния по областям",
            "Активная сетевая проверка: не выполнялась",
            "Ядро Xray: работает",
            "  Проверка xray_process_consistent: успешно",
            "Перехват: не поддерживается",
            "  Проверка interception_active: не поддерживается, причина interception_not_observed",
            "Доступность VPN: не проверено",
            "  Проверка vpn_reachable: не проверено, причина network_check_not_performed (сетевая проверка)",
            "DNS и порт 53: исключение 53 включено, не проверено",
            "  Проверка dns_port_53_path: не проверено, причина network_check_not_performed (сетевая проверка)",
            "  Запись 53 в списке исключённых портов: да; диапазон с этим портом: нет",
            "  Запись 53 в списке перехватываемых портов: нет; диапазон с этим портом: нет",
            "  proxy_dns: present (off); proxy_router: present (off)",
            "  Фактический перехват DNS не проверялся: это факты файлов, а не состояние трафика. "
            "Отсутствие исключения само по себе не ошибка и не доказательство перехвата.",
            f"  Подсказка: {PORT_53_HINT}",
            "Автозапуск: включён",
            "  Проверка autostart_flag_unambiguous: успешно",
            "Режим резерва: без прямого резерва",
            "  Проверка fallback_profile_consistent: успешно",
            "  kill-switch: present (on); балансировщиков: 1; цель fallback: прямой выход 0, блокировка 1, VPN 0, "
            "не определена 0, не задана 0",
            "Черновик: не поддерживается",
            "  Проверка draft_present: не поддерживается, причина drafts_not_implemented",
            "Это снимок источников на момент чтения: работу VPN, перехват трафика и маршрут клиента он не подтверждает.",
        ])

    def test_source_errors_and_unknown_facts_are_shown_with_the_safe_step(self):
        sources = snapshot_installation_sources()
        sources.process.outcome = OSError("/opt/etc/TEST_ONLY_SECRET")
        document = {"outbounds": [], "routing": {"balancers": {"tag": "fixture-private"}}}
        sources.proxy.xray.outcome = XrayConfigSet((ConfigDocument("04_test.json", json.dumps(document).encode()),))
        lines = present_status_summary(summary_view(sources))
        text = self.assert_safe_lines(lines)
        self.assertEqual(lines[2:7], [
            "Ядро Xray: не проверено",
            "  Проверка xray_process_consistent: не проверено, причина xray_process_unavailable",
            "  Отказ: source_failed / xray_process_unavailable",
            "  Причина: Не удалось наблюдать процесс Xray и маркер готовности.",
            f"  Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}",
        ])
        self.assertIn(
            "  kill-switch: present (on); балансировщиков: нет данных; цель fallback: прямой выход нет данных, "
            "блокировка нет данных, VPN нет данных, не определена нет данных, не задана нет данных", lines,
        )
        self.assertIn("Режим резерва: не поддерживается", lines)
        self.assertNotIn("TEST_ONLY_SECRET", text)
        self.assertNotIn("fixture-private", text)
        unconnected = present_status_summary(summary_view(connected=False))
        dns = unconnected.index("DNS и порт 53: не проверено")
        self.assertEqual(unconnected[dns + 1:dns + 3], [
            "  Проверка dns_port_53_path: не проверено, причина source_not_connected (сетевая проверка)",
            f"  Подсказка: {PORT_53_HINT}",
        ])
        self.assertNotIn("Следующий шаг", "\n".join(unconnected))

    def test_unsupported_balancer_is_shown_as_not_supported(self):
        # Регрессия review 73-R01: шапка и пункт не показывают профиль резерва для неподдержанного балансировщика.
        sources = snapshot_installation_sources()
        document = {
            "outbounds": [{"tag": "block-out", "protocol": "blackhole"}],
            "routing": {"balancers": [{"tag": "group-a", "selector": 7, "fallbackTag": "block-out"}]},
        }
        sources.proxy.xray.outcome = XrayConfigSet((ConfigDocument("04_test.json", json.dumps(document).encode()),))
        view = summary_view(sources)
        self.assertIn("  Режим резерва: не поддерживается", present_status_header(view))
        self.assertIn(
            "  Проверка fallback_profile_consistent: не поддерживается, причина fallback_not_resolved",
            present_status_summary(view),
        )

    def test_values_outside_catalogs_are_hidden_and_never_shown_as_success(self):
        view = summary_view()
        payload = view.to_dict()
        core, interception = view.areas[0], view.areas[1]
        object.__setattr__(core, "state", "running")
        object.__setattr__(interception, "area", "interception")
        self.assertEqual(present_status_header(view)[1:3], [f"  Ядро Xray: {HIDDEN}", f"  {HIDDEN}: не поддерживается"])
        # Статус строкой вместо перечисления не становится «успешно»: подпись скрыта.
        object.__setattr__(core.check, "status", "passed")
        self.assertEqual(present_status_header(view)[1], f"  Ядро Xray: {HIDDEN}, {HIDDEN}")
        self.assertIn(f"Проверка xray_process_consistent: {HIDDEN}", "\n".join(present_status_summary(view)))
        object.__setattr__(view, "active_network_check", "no")
        self.assertEqual(present_status_header(view)[0], f"Состояние по источникам, активная сетевая проверка {HIDDEN}:")
        for present in (present_status_header, present_status_summary):
            with self.subTest(presenter=present.__name__):
                with self.assertRaises(TypeError):
                    present(view.areas)
                with self.assertRaises(TypeError):
                    present(payload)


DEVICE_SAFE_MARKERS = tuple(marker for marker in PRIVATE_MARKERS if marker != "device-")
"""Маркеры снимка без `device-`: имена регистраций снимка совпадают с именами хостов и показываются по решению."""


class DeviceListPresenterTests(PresenterAssertions):
    """Список устройств 5 → 1 на снимке: вводные строки, строки, карточки, фильтр имени и предел номеров."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        sources = snapshot_installation_sources()
        keenetic = InspectKeeneticStateHandler(
            sources.keenetic.policies, sources.keenetic.hotspot, sources.keenetic.registrations, sources.keenetic.runtime,
        )
        result = ListKeeneticDevicesHandler(keenetic).execute(ListKeeneticDevices())
        assert result.succeeded, result.error
        cls.devices = result.data

    def listing(self, view=None):
        with forbid_external_effects():
            listing = present_device_list(self.devices if view is None else view)
        self.assertIs(type(listing), MenuList)
        self.assertEqual((listing.title, listing.item_name), (DEVICES_LIST_TITLE, DEVICES_ITEM_NAME))
        lines = list_lines(listing)
        text = "\n".join(lines)
        self.assertTrue(all(line.isprintable() for line in lines))
        for marker in DEVICE_SAFE_MARKERS:
            self.assertNotIn(marker, text)
        return listing

    def test_snapshot_list_has_header_labels_and_cards_without_macs_or_hosts(self):
        listing = self.listing()
        self.assertEqual(listing.header[:5], (
            "Устройства Keenetic по прочитанному состоянию", "Политик: 3", "  Policy10, Policy20, Policy30",
            "Назначений сегментов: 2; без политики в списке: 0",
            "  Сегмент Bridge0: назначение explicit, политика Policy10, запрет доступа нет, только просмотр нет",
        ))
        self.assertIn(
            "Записей устройств: всего 19; online 12, offline 7, online неизвестно 0; разных MAC 19, записей с повтором MAC 0",
            listing.header,
        )
        self.assertIn(
            "Назначения: явных 15, наследуют 2, без назначения 2, не распознано 0; политики нет в списке 0; "
            "запрет доступа 1; только просмотр 0", listing.header,
        )
        self.assertIn("Регистраций без записи: 0; наблюдений без записи: 0; неоднозначных наблюдений: 0; скрытых имён: 0", listing.header)
        self.assertEqual(listing.header[-2:], (DEVICES_NOTE, presenters.SNAPSHOT_NOTE))
        self.assertEqual([entry.number for entry in listing.entries], list(range(1, 20)))
        self.assertEqual(listing.entries[0].label, "device-01: явная политика Policy10, online, запрет доступа нет, интерфейс Bridge0")
        self.assertEqual(listing.entries[5].label, "device-06: без назначения, offline, запрет доступа да, интерфейс не наблюдался")
        self.assertEqual(listing.entries[11].label, "device-12: наследует политику сегмента, online, запрет доступа нет, интерфейс Bridge0")
        self.assertEqual(listing.entries[16].card, (
            "Позиция записи: 16 (счёт с нуля в ip/hotspot)", "Регистраций: 1", "  device-17",
            "Назначение: explicit — явная политика Policy30; в списке политик: да", "Online: offline; причина: нет",
            "Запрет доступа: нет; только просмотр: нет; MAC повторяется: нет", "Наблюдаемый интерфейс: Bridge0",
            "Сегмент по интерфейсу: назначение сегмента с этим интерфейсом",
            "  Сегмент Bridge0: назначение explicit, политика Policy10, запрет доступа нет, только просмотр нет",
            SEGMENT_MATCH_NOTE, DEVICES_NOTE,
        ))
        # Строка и карточка собраны из одних значений: имя в строке совпадает с единственной регистрацией карточки.
        for entry in listing.entries:
            self.assertEqual(entry.label.split(":")[0], entry.card[2].strip())
        for wrong in (self.devices.devices, self.devices.devices[0], self.results["keenetic"].data):
            with self.subTest(wrong=type(wrong).__name__), self.assertRaises(TypeError):
                present_device_list(wrong)

    def test_hidden_absent_and_several_names_and_each_catalog_value_are_shown(self):
        first = self.devices.devices[0]
        hidden = replace(first, registration_names=(None,), name=None)
        absent = replace(first, registration_count=0, registration_names=(), name_known=False, name=None)
        several = replace(first, registration_count=2, registration_names=("Телефон", None), name_known=False, name=None)
        missing = replace(first, policy_id="Policy9", policy_present=False)
        inherit = replace(first, assignment="inherit", policy_id=None, policy_present=None)
        unknown = replace(first, assignment="unknown", policy_id=None, policy_present=None, read_only=True)
        unseen = replace(
            first, presence="unknown", presence_reason="no_observation", observed_interface_known=False,
            observed_interface_id=None, segment_match="not_observed", segment=None,
        )
        ambiguous = replace(first, presence="unknown", presence_reason="ambiguous_observation", mac_duplicate=True)
        active = replace(first, presence="unknown", presence_reason="active_unknown", segment_match="ambiguous", segment=None)
        hidden_interface = replace(first, observed_interface_id=None, segment_match="unassigned", segment=None)
        entries = (hidden, absent, several, missing, inherit, unknown, unseen, ambiguous, active, hidden_interface)
        entries = tuple(replace(item, position=position) for position, item in enumerate(entries))
        counts = DeviceCountsView(
            record_count=10, distinct_mac_count=10, duplicate_mac_count=1, online_count=7, offline_count=0, unknown_count=3,
            explicit_count=8, inherit_count=1, unassigned_count=0, unknown_assignment_count=1, missing_policy_count=1,
            access_denied_count=0, read_only_count=1, hidden_name_count=2, ambiguous_observation_count=1,
            registrations_without_device_count=0, runtime_without_device_count=0,
        )
        view = DeviceListView(
            2, ("Policy10", "Policy30"), self.devices.segments, 0, counts, entries,
        )
        listing = self.listing(view)
        labels = [entry.label for entry in listing.entries]
        self.assertEqual(labels[0], "<скрыто>: явная политика Policy10, online, запрет доступа нет, интерфейс Bridge0")
        self.assertTrue(labels[1].startswith("без регистрации: "))
        self.assertTrue(labels[2].startswith("регистраций 2: "))
        self.assertIn(": явная политика Policy9 (нет в списке политик), online", labels[3])
        self.assertIn(": наследует политику сегмента, online", labels[4])
        self.assertIn(": назначение не распознано, online", labels[5])
        self.assertIn(", online неизвестно, запрет доступа нет, интерфейс не наблюдался", labels[6])
        cards = [entry.card for entry in listing.entries]
        self.assertEqual(cards[0][1:3], ("Регистраций: 1", "  <скрыто>"))
        self.assertEqual(cards[1][1:2], ("Регистраций: 0",))
        self.assertEqual(cards[2][1:4], ("Регистраций: 2", "  Телефон", "  <скрыто>"))
        self.assertIn("Назначение: explicit — явная политика Policy9 (нет в списке политик); в списке политик: нет", cards[3])
        self.assertIn("Назначение: unknown — назначение не распознано; в списке политик: нет данных", cards[5])
        self.assertIn("Запрет доступа: нет; только просмотр: да; MAC повторяется: нет", cards[5])
        self.assertIn("Online: online неизвестно; причина: наблюдения нет", cards[6])
        self.assertIn("Сегмент по интерфейсу: интерфейс не наблюдался", cards[6])
        self.assertIn("Online: online неизвестно; причина: наблюдение неоднозначно: MAC повторяется", cards[7])
        self.assertIn("Запрет доступа: нет; только просмотр: нет; MAC повторяется: да", cards[7])
        self.assertIn("Online: online неизвестно; причина: признак активности не распознан", cards[8])
        self.assertIn("Сегмент по интерфейсу: несколько назначений сегментов с этим интерфейсом", cards[8])
        self.assertIn("Наблюдаемый интерфейс: <скрыто>", cards[9])
        self.assertIn("Сегмент по интерфейсу: назначения сегмента с этим интерфейсом нет", cards[9])
        self.assertTrue(all("  Сегмент " not in line for index in (6, 8, 9) for line in cards[index]))
        self.assertTrue(any(line.startswith("  Сегмент Bridge0") for line in cards[7]))
        # Подписи берутся только из каталогов application: чужое значение не выводится.
        for value in ("direct", "online ", None, 1, presenters.HIDDEN):
            with self.subTest(value=value):
                self.assertEqual(presenters._catalog(presenters.ASSIGNMENT_LABELS, value), HIDDEN)

    def test_device_name_follows_the_user_text_rule(self):
        for value in ("Телефон", "a", "x" * 64, "name with spaces", "«кавычки»", "1"):
            with self.subTest(value=value):
                self.assertEqual(device_name(value), value)
        for value in ("", " x", "x ", "x" * 65, "a\x1bb", "a\nb", "a\tb", "​x", None, 5, b"x", "\ud800"):
            with self.subTest(value=repr(value)):
                self.assertEqual(device_name(value), HIDDEN)

    def test_keenetic_state_segment_lines_are_unchanged_after_sharing_the_helper(self):
        lines = present_keenetic_state(self.results["keenetic"].data)
        self.assertEqual(
            lines[3:5],
            ["  Сегмент Bridge0: назначение explicit, политика Policy10, запрет доступа нет, только просмотр нет",
             "  Сегмент Bridge1: назначение unassigned, политика нет данных, запрет доступа да, только просмотр нет"],
        )

    def test_many_long_policy_ids_are_split_into_lines_within_the_limit(self):
        # Регрессия review 75-R02: 31 ID по 64 символа в одной строке превышали предел строки списка.
        long_ids = tuple(f"Policy{number:02d}" + "x" * 56 for number in range(31))
        view = replace(self.devices, policy_count=3 + len(long_ids), policy_ids=(*self.devices.policy_ids, *long_ids))
        listing = self.listing(view)
        self.assertEqual(listing.header[1], "Политик: 34")
        self.assertEqual(listing.header[2], "  Policy10, Policy20, Policy30, " + ", ".join(long_ids[:7]))
        self.assertEqual(listing.header[5], "  " + ", ".join(long_ids[27:31]))
        self.assertTrue(listing.header[6].startswith("Назначений сегментов: "))
        self.assertTrue(all(len(line) <= MAX_LIST_LINE_LENGTH for line in list_lines(listing)))
        empty = replace(
            self.devices, policy_count=0, policy_ids=(), segments=(), segment_missing_policy_count=0,
            counts=replace(self.devices.counts, missing_policy_count=15),
            devices=tuple(
                replace(item, policy_present=False if item.policy_present is not None else None,
                        observed_interface_id=None, segment_match="unassigned" if item.observed_interface_known else "not_observed",
                        segment=None)
                for item in self.devices.devices
            ),
        )
        self.assertEqual(self.listing(empty).header[1:3], ("Политик: 0", "  нет"))

    def test_more_records_than_numbers_are_cut_with_a_note(self):
        template = DeviceEntryView(
            0, 0, (), False, None, "unassigned", None, None, "online", None, False, False, False, False, None,
            "not_observed", None,
        )
        entries = tuple(replace(template, position=position) for position in range(MAX_ITEM_NUMBER + 1))
        counts = DeviceCountsView(
            record_count=len(entries), distinct_mac_count=len(entries), duplicate_mac_count=0, online_count=len(entries),
            offline_count=0, unknown_count=0, explicit_count=0, inherit_count=0, unassigned_count=len(entries),
            unknown_assignment_count=0, missing_policy_count=0, access_denied_count=0, read_only_count=0,
            hidden_name_count=0, ambiguous_observation_count=0, registrations_without_device_count=0,
            runtime_without_device_count=0,
        )
        listing = self.listing(DeviceListView(0, (), (), 0, counts, entries))
        self.assertEqual(len(listing.entries), MAX_ITEM_NUMBER)
        self.assertEqual(listing.entries[-1].number, MAX_ITEM_NUMBER)
        self.assertEqual(listing.header[-1], f"Записей больше {MAX_ITEM_NUMBER}: в списке первые {MAX_ITEM_NUMBER}, остальные не показываются.")
        self.assertTrue(all(len(line) <= MAX_LIST_LINE_LENGTH for line in list_lines(listing)))


class RouteExplanationPresenterTests(PresenterAssertions):
    """Объяснение маршрута: предположения, схема, шаги и четыре итога без введённых значений и значений условий."""

    ENTERED = ("sub.example.test", "service.another.test", "198.51.100.7", "2001:db8::7")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        "пример.рф".encode("idna")
        sources = snapshot_installation_sources()
        proxy = InspectProxyConfigHandler(sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists)
        routing = ImportRoutingSchemeHandler(proxy)
        cls.absent = ExplainRouteHandler.from_import(routing, InMemoryManagerMetadataStore()).execute(
            ExplainRoute(destination="sub.example.test"),
        ).data
        sources.proxy.xray.outcome = XrayConfigSet((
            ConfigDocument("04_outbounds.json", json.dumps({"outbounds": [
                {"tag": "proxy-out", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"},
            ]}).encode("utf-8")),
            ConfigDocument("05_routing.json", json.dumps({"routing": {"rules": [
                {"type": "field", "domain": ["domain:example.test"], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:ru"], "outboundTag": "proxy-out"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"},
            ]}}).encode("utf-8")),
        ))
        rules = scheme_rules(import_routing_scheme(sources.proxy.xray.outcome))
        records = (RuleRecord(fixed_id(1), NAME_MARKER, rule_key(rules[0])), RuleRecord(fixed_id(2), None, rule_key(rules[1])))
        store = InMemoryManagerMetadataStore(encode_manager_metadata(ManagerMetadata(None, UnknownFields(), rules=records)))
        handler = ExplainRouteHandler.from_import(routing, store)
        cls.selected = handler.execute(ExplainRoute(destination="sub.example.test")).data
        cls.unknown = handler.execute(ExplainRoute(destination="service.another.test 198.51.100.7")).data
        failing = InMemoryManagerMetadataStore()
        failing.read_failure = ManagerMetadataStoreError(MetadataStoreFailure.BUSY)
        cls.failed_store = ExplainRouteHandler.from_import(routing, failing).execute(
            ExplainRoute(destination="sub.example.test"),
        ).data
        policy = RoutingPolicy((RoutingRule(IPCondition("198.51.100.0/24"), RoutingAction.DIRECT),), FinalRoutingRule(RoutingAction.BLOCK))
        cls.port_final = ExplainRouteHandler(InMemoryRoutingPolicySource(policy)).execute(
            ExplainRoute(destination="2001:db8::7"),
        ).data

    def lines(self, view):
        with forbid_external_effects():
            lines = present_route_explanation(view)
        text = self.assert_safe_lines(lines)
        for marker in (*self.ENTERED, "example.test", "198.51.100.0", "geoip:", '"ru"'):
            self.assertNotIn(marker, text)
        return lines

    def test_policy_absent_on_snapshot_names_the_state_and_reasons(self):
        lines = self.lines(self.absent)
        self.assertEqual(lines[:2], ["Предварительный расчёт маршрута", ROUTE_NOTE])
        self.assertEqual(lines[2], "Предположения расчёта:")
        self.assertEqual(len([line for line in lines[3:8] if line.startswith("  ")]), 5)
        self.assertIn("Адресов в расчёте: нет данных", lines)
        self.assertIn(
            "Схема: часть 05_routing.json; только просмотр да; групп 8; правил модели 40; политика не собрана; "
            "причины: final_rule_unresolved",
            lines,
        )
        self.assertIn(METADATA_NOTES[MetadataState.ABSENT], lines)
        self.assertIn("Шагов проверки: 0", lines)
        self.assertEqual(lines[-2:], [f"Итог: {OUTCOME_LABELS[RouteOutcome.POLICY_ABSENT.value]}", "  " + POLICY_ABSENT_NOTE])

    def test_selected_rule_shows_steps_identity_and_ambiguous_target_position(self):
        lines = self.lines(self.selected)
        self.assertIn(METADATA_NOTES[MetadataState.PRESENT], lines)
        self.assertIn("Шагов проверки: 1", lines)
        self.assertIn(
            f"  Шаг 1: правило 0 (группа 0, правило 0 в группе) — DomainCondition, действие DIRECT, совпало; "
            f"Проверено имя с учётом режима точного совпадения или поддоменов.; ID {fixed_id(1)}; название «{NAME_MARKER}»",
            lines,
        )
        self.assertIn(f"Итог: {OUTCOME_LABELS[RouteOutcome.RULE.value]}", lines)
        self.assertIn(f"  Выбрано правило 0 (группа 0, правило 0 в группе): действие DIRECT; ID {fixed_id(1)}; название «{NAME_MARKER}»", lines)
        self.assertIn("  Назначение: outbound direct; позиция: 04_outbounds.json, индекс 1", lines)
        # Повтор тега делает политику несобираемой, поэтому состояние позиции проверяется на представлении.
        ambiguous = replace(self.selected, selection=replace(
            self.selected.selection, target_position_state=TargetPositionState.AMBIGUOUS, target_position=None,
        ))
        self.assertIn(
            f"  Назначение: outbound direct; позиция: {TARGET_POSITION_LABELS[TargetPositionState.AMBIGUOUS]}",
            self.lines(ambiguous),
        )

    def test_unknown_geodata_names_the_step_and_never_a_route(self):
        lines = self.lines(self.unknown)
        self.assertIn("Адресов в расчёте: 1", lines)
        self.assertIn(
            f"  Шаг 2: правило 1 (группа 1, правило 0 в группе) — GeoIPCondition, действие VPN, неизвестно; "
            f"Источник содержимого геобазы не передан.; ID {fixed_id(2)}; название не задано",
            lines,
        )
        self.assertEqual(lines[-3:], [
            f"Итог: {OUTCOME_LABELS[RouteOutcome.UNKNOWN.value]}", "  Правило не выбрано: условие на шаге 2 неизвестно.",
            "  " + UNKNOWN_ROUTE_NOTE,
        ])
        self.assertFalse(any("Выбрано" in line or "Назначение" in line for line in lines))

    def test_failed_store_shows_its_error_with_step_and_keeps_the_explanation(self):
        lines = self.lines(self.failed_store)
        self.assertIn(METADATA_NOTES[MetadataState.FAILED], lines)
        self.assertIn("  Отказ: source_failed / metadata_store_busy", lines)
        self.assertIn(f"  Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.RETRY_LATER]}", lines)
        self.assertIn("  Выбрано правило 0 (группа 0, правило 0 в группе): действие DIRECT; ID не присвоен; название не задано", lines)

    def test_final_over_the_port_has_no_scheme_lines_and_no_target(self):
        lines = self.lines(self.port_final)
        self.assertFalse(any(line.startswith("Схема:") for line in lines))
        self.assertFalse(any(line in METADATA_NOTES.values() for line in lines))
        self.assertIn("  Шаг 2: правило 1 — финальное правило, действие BLOCK, совпало; "
                      "Все включённые условия проверены и не совпали; выбрано финальное правило.", lines)
        self.assertEqual(lines[-3:], [
            f"Итог: {OUTCOME_LABELS[RouteOutcome.FINAL.value]}",
            "  Ни одно включённое правило не совпало: действует финальное правило 1 — действие BLOCK",
            f"  Назначение: {MISSING}",
        ])

    def test_values_outside_formats_and_catalogs_are_hidden(self):
        step = replace(self.selected.steps[0], reason="tag\x1b", condition_type="private.example.test", action="x y")
        hidden = replace(self.selected, steps=(step,), outcome=self.selected.outcome)
        lines = self.lines(hidden)
        shown = [line for line in lines if line.startswith("  Шаг 1")][0]
        self.assertNotIn("private.example", shown)
        self.assertNotIn("x y", shown)
        self.assertEqual(shown.count(HIDDEN), 3)
        with self.assertRaises(TypeError):
            present_route_explanation(self.results["routing"].data)


def quick_check_view(sources=None, *, connected=True):
    sources = snapshot_installation_sources() if sources is None else sources
    proxy = None
    if connected:
        proxy = InspectProxyConfigHandler(sources.proxy.xray, sources.proxy.settings, sources.proxy.init, sources.proxy.lists)
    handler = QuickCheckHandler(proxy, sources.process if connected else None, sources.geodata if connected else None)
    result = handler.execute(QuickCheck())
    assert result.succeeded
    return result.data


QUICK_CHECK_LINES = [
    "Быстрая проверка без изменений",
    "Активная сетевая проверка: не выполнялась",
    "Итог: расхождений не найдено, часть проверок не выполнена или не поддерживается; "
    "успешно 6, ошибка 0, не проверено 2, не поддерживается 1",
    "Источники:",
    "  части конфигурации Xray: прочитан",
    "  настройки XKeen: прочитан",
    "  параметры init XKeen: прочитан",
    "  список исключённых портов: прочитан",
    "  список перехватываемых портов: прочитан",
    "  процесс Xray: прочитан",
    "  инвентарь геобаз: прочитан",
    "Проверки:",
    "  xray_config_consistent: успешно",
    "  geodata_references_resolved: успешно",
    "  fallback_profile_consistent: успешно",
    "  autostart_flag_unambiguous: успешно",
    "  dns_port_53_mode_consistent: успешно",
    "  xray_process_consistent: успешно",
    "  interception_active: не поддерживается, причина interception_not_observed",
    "  dns_port_53_path: не проверено, причина network_check_not_performed (сетевая проверка)",
    "  vpn_reachable: не проверено, причина network_check_not_performed (сетевая проверка)",
    PORT_53_NOTE,
    DNS_PRITUNL_NOTE,
    SNAPSHOT_NOTE,
]


class QuickCheckPresenterTests(PresenterAssertions):
    """Пункт 1 → 7: итог, источники и проверки из каталогов application, оговорки, скрытие значений вне каталогов."""

    def test_snapshot_quick_check_lists_outcome_sources_checks_and_notes(self):
        view = quick_check_view()
        with forbid_external_effects():
            lines = present_quick_check(view)
        self.assert_safe_lines(lines)
        self.assertEqual(lines, QUICK_CHECK_LINES)

    def test_source_failure_is_shown_once_with_its_step_and_discrepancy_changes_the_outcome(self):
        sources = snapshot_installation_sources()
        sources.geodata.outcome = OSError("/opt/etc/TEST_ONLY_SECRET")
        sources.process.outcome = XrayProcessObservation((4242, 4243), True)
        lines = present_quick_check(quick_check_view(sources))
        text = self.assert_safe_lines(lines)
        self.assertEqual(lines[2], "Итог: найдены расхождения; успешно 4, ошибка 1, не проверено 3, не поддерживается 1")
        geodata = lines.index("  инвентарь геобаз: отказ")
        self.assertEqual(lines[geodata + 1:geodata + 4], [
            "    Отказ: source_failed / geo_databases_unavailable",
            "    Причина: Не удалось прочитать инвентарь файлов геобаз.",
            f"    Следующий шаг: {NEXT_STEP_MESSAGES[NextStepCode.CHECK_SOURCE]}",
        ])
        self.assertIn("  geodata_references_resolved: не проверено, причина geo_databases_unavailable", lines)
        self.assertIn("  xray_process_consistent: ошибка, причина multiple_processes", lines)
        self.assertEqual(text.count("Следующий шаг"), 1)
        self.assertNotIn("TEST_ONLY_SECRET", text)
        self.assertNotIn("4243", text)

    def test_unconnected_sources_are_shown_without_success(self):
        lines = present_quick_check(quick_check_view(connected=False))
        text = self.assert_safe_lines(lines)
        self.assertIn("  части конфигурации Xray: не подключён", lines)
        self.assertIn("  инвентарь геобаз: не подключён", lines)
        self.assertIn("  xray_process_consistent: не проверено, причина source_not_connected", lines)
        self.assertEqual(lines[2], "Итог: расхождений не найдено, часть проверок не выполнена или не поддерживается; "
                                   "успешно 0, ошибка 0, не проверено 8, не поддерживается 1")
        self.assertNotIn(": успешно", text)
        self.assertNotIn("Следующий шаг", text)

    def test_values_outside_catalogs_are_hidden_and_never_shown_as_success(self):
        view = quick_check_view()
        payload = view.to_dict()
        object.__setattr__(view, "outcome", "incomplete")
        object.__setattr__(view.sources[0], "state", "read")
        object.__setattr__(view.sources[1], "source", "settings")
        object.__setattr__(view.checks.items[0], "status", "passed")
        lines = present_quick_check(view)
        self.assertTrue(lines[2].startswith(f"Итог: {HIDDEN}; успешно "))
        self.assertEqual(lines[4:6], [f"  части конфигурации Xray: {HIDDEN}", f"  {HIDDEN}: прочитан"])
        self.assertEqual(lines[12], f"  xray_config_consistent: {HIDDEN}")
        with self.assertRaises(TypeError):
            present_quick_check(payload)
        with self.assertRaises(TypeError):
            present_quick_check(view.checks)


if __name__ == "__main__":
    unittest.main()
