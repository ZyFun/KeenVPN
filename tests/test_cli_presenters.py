"""Текстовые представления результатов на обезличенном снимке: подписи, безопасность, отказы."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.contract import CONTRACT_VERSION, ErrorCategory, ErrorDetail, Result, failed, succeeded
from dataclasses import replace

from keenvpn.application.installation import GeoDatabaseFileView, InspectInstallation, InspectInstallationHandler
from keenvpn.application.keenetic_state import InspectKeeneticState, InspectKeeneticStateHandler
from keenvpn.application.manager_metadata import (
    ImportStoragePlacement, ImportStoragePlacementHandler, InspectManagerMetadata, InspectManagerMetadataHandler,
)
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler
from keenvpn.interfaces.cli import presenters
from keenvpn.interfaces.cli.presenters import (
    HIDDEN, MISSING, count, digest, file_name, flag, geo_source, geo_version, identifier, identifiers, interface_id,
    known_value, optional_count, optional_digest, optional_file_name, optional_flag, optional_identifier, present_about, present_error, present_geodata, present_installation, present_keenetic_state,
    present_manager_metadata, present_port53, present_proxy_summary, present_result, present_routing_scheme,
    present_xray_process, safe_text,
)
from keenvpn.interfaces.cli.menu import MAX_ITEM_NUMBER, MAX_LIST_LINE_LENGTH, MenuList
from keenvpn.interfaces.cli.presenters import ROUTING_ITEM_NAME, ROUTING_LIST_TITLE
from keenvpn.interfaces.cli.terminal import UNAVAILABLE_MARK
import json

from keenvpn.adapters.xray_configs import xray_config_from_files
from tests.support.in_memory import InMemoryManagerMetadataStore, InMemoryStoragePlacementSource
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import (
    SYNTHETIC_GEOIP_SHA256, SYNTHETIC_HISTORY_RETENTION, SYNTHETIC_HISTORY_SIZE, SYNTHETIC_STORAGE_ID,
    SYNTHETIC_STORAGE_ROOT, load_xray_snapshot_files, snapshot_installation_sources, synthetic_storage_placement,
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


class SnapshotPresenterTests(PresenterAssertions):
    def test_installation_summary_names_four_areas_and_disclaimer(self):
        view = self.results["installation"].data
        with forbid_external_effects():
            lines = present_installation(view)
        text = self.assert_safe_lines(lines)
        self.assertEqual(lines[0], "Сводка установки по прочитанным источникам")
        for area in ("  Keenetic", "  Xray", "  XKeen", "  Геобазы", "  Процесс Xray"):
            self.assertIn(area, lines)
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
        self.assertEqual(present_error(error), [
            f"Отказ: invalid_source_data / {HIDDEN}", f"Уточнение: {HIDDEN}", f"Причина: {HIDDEN}",
        ])
        plain = ErrorDetail(ErrorCategory.UNSUPPORTED, "storage_placement_mismatch", "Текст.")
        self.assertEqual(present_error(plain), ["Отказ: unsupported / storage_placement_mismatch", "Причина: Текст."])
        with self.assertRaises(TypeError):
            present_error({"code": "x"})
        # Успешный результат любого сценария отдаётся переданному представлению как есть.
        data = _Data()
        self.assertEqual(present_result(succeeded("op", "cmd", data), lambda view: [repr(view is data)]), ["True"])


class _Data:
    def to_dict(self):
        return {}


if __name__ == "__main__":
    unittest.main()
