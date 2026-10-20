"""Общий словарь статусов проверок, признак активной сетевой проверки и построители проверок."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.checks import (
    CHECK_STATUS_LABELS, GEODATA_REFERENCES_CHECK, VPN_REACHABLE_CHECK, XRAY_PROCESS_CHECK, CheckReason,
    CheckView, ChecksView, geodata_references_check, vpn_reachability_not_checked, xray_process_check,
)
from keenvpn.application.contract import CheckStatus, OperationStatus
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.geodata import (
    GEOIP_FILE_NAME, GEOSITE_FILE_NAME, GeoDatabaseFile, GeoDatabaseInventory, GeoDataState, assemble_geodata_state,
)
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


PRIVATE = "fixture-private.example"


def passive(*items: CheckView) -> ChecksView:
    return ChecksView(False, items)


def geodata_state(*values: str, files: tuple[GeoDatabaseFile, ...] | None = None) -> GeoDataState:
    """Состояние геобаз из значений поля `ip` одного правила и инвентаря по умолчанию."""
    rule = {"type": "field", "ip": list(values), "outboundTag": "direct"}
    config = XrayConfigSet((ConfigDocument("05_routing.json", json.dumps({"routing": {"rules": [rule]}}).encode()),))
    inventory = GeoDatabaseInventory(files if files is not None else (
        GeoDatabaseFile(GEOIP_FILE_NAME, True, 1024, "3f" * 32), GeoDatabaseFile(GEOSITE_FILE_NAME, False),
    ))
    return assemble_geodata_state(inventory, config)


class CheckStatusTests(unittest.TestCase):
    def test_dictionary_has_exactly_four_statuses_with_stable_codes(self):
        self.assertEqual([status.value for status in CheckStatus], ["passed", "failed", "not_checked", "unsupported"])
        self.assertEqual(set(CHECK_STATUS_LABELS), set(CheckStatus))
        self.assertEqual(
            [CHECK_STATUS_LABELS[status] for status in CheckStatus],
            ["успешно", "ошибка", "не проверено", "не поддерживается"],
        )
        self.assertEqual(len(set(CHECK_STATUS_LABELS.values())), 4)
        for label in CHECK_STATUS_LABELS.values():
            self.assertTrue(label.isprintable())

    def test_status_is_a_different_type_from_operation_status(self):
        # Сценарий завершается `succeeded`, а его проверки могут быть «ошибка», «не проверено» или «не поддерживается».
        self.assertIsNot(type(CheckStatus.FAILED), type(OperationStatus.FAILED))
        self.assertFalse(issubclass(CheckStatus, OperationStatus))
        self.assertEqual({status.value for status in OperationStatus} & {status.value for status in CheckStatus}, {"failed"})
        # Совпадающая строка `failed` не делает статусы взаимозаменяемыми: модели требуют точный тип.
        with self.assertRaises(TypeError):
            CheckView(XRAY_PROCESS_CHECK, OperationStatus.FAILED, False, None)
        with self.assertRaises(TypeError):
            CheckView(XRAY_PROCESS_CHECK, "failed", False, None)

    def test_labels_table_is_read_only(self):
        self.assertIs(type(CHECK_STATUS_LABELS), MappingProxyType)
        with self.assertRaises(TypeError):
            CHECK_STATUS_LABELS[CheckStatus.PASSED] = "иначе"
        with self.assertRaises(TypeError):
            del CHECK_STATUS_LABELS[CheckStatus.PASSED]


class CheckViewTests(unittest.TestCase):
    def test_view_is_frozen_and_serialises_stable_codes(self):
        check = CheckView(XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, CheckReason.PROCESS_WITHOUT_MARKER.value)
        payload = check.to_dict()
        self.assertEqual(payload, {
            "code": "xray_process_consistent", "status": "failed", "network": False, "reason": "process_without_marker",
        })
        self.assertEqual(json.loads(json.dumps(payload)), payload)
        self.assertEqual(list(payload), ["code", "status", "network", "reason"])
        with self.assertRaises(FrozenInstanceError):
            check.status = CheckStatus.PASSED
        self.assertIsNone(CheckView(XRAY_PROCESS_CHECK, CheckStatus.PASSED, False, None).reason)

    def test_view_rejects_wrong_types_and_malformed_codes(self):
        for args in (
            ("Проверка", CheckStatus.PASSED, False, None),
            ("bad code!", CheckStatus.PASSED, False, None),
            (PRIVATE, CheckStatus.PASSED, False, None),
            ("x" * 65, CheckStatus.PASSED, False, None),
            (None, CheckStatus.PASSED, False, None),
            (XRAY_PROCESS_CHECK, None, False, None),
            (XRAY_PROCESS_CHECK, CheckStatus.PASSED, 0, None),
            (XRAY_PROCESS_CHECK, CheckStatus.PASSED, None, None),
            (XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, "bad reason!"),
            (XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, PRIVATE),
            (XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, CheckReason.PROCESS_WITHOUT_MARKER),
            (XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, b"reason"),
        ):
            with self.subTest(args=args), self.assertRaises(TypeError):
                CheckView(*args)

    def test_reason_codes_are_stable_identifiers(self):
        for reason in CheckReason:
            with self.subTest(reason=reason.value):
                self.assertRegex(reason.value, r"\A[a-z][a-z0-9_]{2,63}\Z")
                CheckView(XRAY_PROCESS_CHECK, CheckStatus.NOT_CHECKED, False, reason.value)


class ChecksViewTests(unittest.TestCase):
    def test_passive_result_cannot_claim_a_network_check_outcome(self):
        # Признак задаёт сценарий; без активной проверки сетевая проверка не может быть «успешно» или «ошибка».
        for status in (CheckStatus.PASSED, CheckStatus.FAILED):
            with self.subTest(status=status.value), self.assertRaises(TypeError):
                passive(CheckView(VPN_REACHABLE_CHECK, status, True, None))
        for status in (CheckStatus.NOT_CHECKED, CheckStatus.UNSUPPORTED):
            with self.subTest(status=status.value):
                view = passive(CheckView(VPN_REACHABLE_CHECK, status, True, CheckReason.NETWORK_CHECK_NOT_PERFORMED.value))
                self.assertIs(view.active_network_check, False)
        # Активный результат может нести итог сетевой проверки, но это не делает его пассивным просмотром.
        active = ChecksView(True, (CheckView(VPN_REACHABLE_CHECK, CheckStatus.FAILED, True, None),))
        self.assertIs(active.active_network_check, True)
        self.assertEqual(active.to_dict()["active_network_check"], True)

    def test_items_are_unique_exact_views_in_a_tuple(self):
        check = CheckView(XRAY_PROCESS_CHECK, CheckStatus.PASSED, False, None)

        class Derived(CheckView):
            pass

        for args in (
            (False, [check]),
            (False, (check, check)),
            (False, (check, CheckView(XRAY_PROCESS_CHECK, CheckStatus.FAILED, False, None))),
            (False, (Derived(XRAY_PROCESS_CHECK, CheckStatus.PASSED, False, None),)),
            (False, ("check",)),
            (None, (check,)),
            (1, (check,)),
        ):
            with self.subTest(args=args), self.assertRaises(TypeError):
                ChecksView(*args)
        empty = passive()
        self.assertEqual(empty.to_dict(), {"active_network_check": False, "items": []})

    def test_to_dict_keeps_order_and_round_trips(self):
        view = passive(
            xray_process_check(XrayProcessObservation((4242,), True)),
            vpn_reachability_not_checked(),
        )
        payload = view.to_dict()
        self.assertEqual(list(payload), ["active_network_check", "items"])
        self.assertEqual([item["code"] for item in payload["items"]], [XRAY_PROCESS_CHECK, VPN_REACHABLE_CHECK])
        self.assertEqual(json.loads(json.dumps(payload, ensure_ascii=False)), payload)
        self.assertEqual(view.statuses, {XRAY_PROCESS_CHECK: CheckStatus.PASSED, VPN_REACHABLE_CHECK: CheckStatus.NOT_CHECKED})
        with self.assertRaises(FrozenInstanceError):
            view.items = ()


class BuilderTests(unittest.TestCase):
    def test_process_check_passes_only_for_consistent_observation(self):
        for pids, marker, expected, reason in (
            ((4242,), True, CheckStatus.PASSED, None),
            ((), False, CheckStatus.PASSED, None),
            ((4242,), False, CheckStatus.FAILED, "process_without_marker"),
            ((), True, CheckStatus.FAILED, "marker_without_process"),
            ((4242, 4243), True, CheckStatus.FAILED, "multiple_processes"),
        ):
            with self.subTest(pids=pids, marker=marker):
                check = xray_process_check(XrayProcessObservation(pids, marker))
                self.assertEqual((check.code, check.status, check.network, check.reason), (XRAY_PROCESS_CHECK, expected, False, reason))
                self.assertNotIn("4242", json.dumps(check.to_dict()))
        with self.assertRaises(TypeError):
            xray_process_check({"pids": [4242], "ready_marker": True})

    def test_geodata_check_reaches_every_status_without_values(self):
        cases = (
            ("passed", geodata_state("geoip:ru"), CheckStatus.PASSED, None),
            ("no references", geodata_state(), CheckStatus.NOT_CHECKED, "no_references"),
            ("missing file", geodata_state("geoip:ru", files=(
                GeoDatabaseFile(GEOIP_FILE_NAME, False), GeoDatabaseFile(GEOSITE_FILE_NAME, False),
            )), CheckStatus.FAILED, "missing_files"),
            ("unsupported reference", geodata_state("geoip:ru", "geoip:"), CheckStatus.FAILED, "unsupported_references"),
            ("missing before unsupported", geodata_state("geoip:", files=(
                GeoDatabaseFile(GEOIP_FILE_NAME, False), GeoDatabaseFile(GEOSITE_FILE_NAME, False),
            )), CheckStatus.FAILED, "unsupported_references"),
            ("file not inventoried", geodata_state("ext:fixture-private.dat:x", "geoip:ru"), CheckStatus.UNSUPPORTED, "files_not_inventoried"),
            ("missing wins over unknown", geodata_state("ext:fixture-private.dat:x", "geoip:ru", files=(
                GeoDatabaseFile(GEOIP_FILE_NAME, False), GeoDatabaseFile(GEOSITE_FILE_NAME, False),
            )), CheckStatus.FAILED, "missing_files"),
        )
        for name, state, expected, reason in cases:
            with self.subTest(case=name):
                check = geodata_references_check(state)
                self.assertEqual((check.code, check.status, check.network, check.reason), (GEODATA_REFERENCES_CHECK, expected, False, reason))
                self.assertNotIn("fixture-private", json.dumps(check.to_dict()) + repr(check))
        with self.assertRaises(TypeError):
            geodata_references_check(geodata_state("geoip:ru").to_diagnostic())

    def test_vpn_reachability_is_never_passed_without_a_probe(self):
        check = vpn_reachability_not_checked()
        self.assertEqual(
            (check.code, check.status, check.network, check.reason),
            (VPN_REACHABLE_CHECK, CheckStatus.NOT_CHECKED, True, "network_check_not_performed"),
        )
        self.assertIs(passive(check).items[0], check)


if __name__ == "__main__":
    unittest.main()
