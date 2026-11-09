"""Меню → файловая сессия DATA → полные снимки и проверки на временном корне."""

from contextlib import ExitStack
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.draft_session_files import DRAFT_FILE_NAME, DraftSessionFiles
from keenvpn.adapters.geodata_files import XRAY_ASSET_DIRECTORY
from keenvpn.adapters.keenetic_rci_http import RciResource
from keenvpn.adapters.router_manager_files import DRAFT_DIRECTORY, connect_router_manager_files
from keenvpn.adapters.router_sources import GeoCandidateFiles, GeoDatabaseFiles, SourceFingerprints
from keenvpn.adapters.xkeen_files import XKEEN_INIT_PATH, XKEEN_LIST_DIRECTORY, XKEEN_SETTINGS_PATH
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY
from keenvpn.application.contract import NEXT_STEP_MESSAGES, ErrorCategory, ErrorDetail, NextStepCode
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.domain.draft_session import encode_draft_session
from keenvpn.domain.source_baseline import BaselineSource
from keenvpn.domain.xkeen_config import XKeenListName
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.interfaces.cli import composition, entrypoints
from keenvpn.interfaces.cli.composition import MenuSources, assemble_main_menu
from keenvpn.interfaces.cli.menu import UnavailableReason
from tests import test_storage_placement_files as placement
from tests.test_router_manager_files import read_only
from tests.support import saved_draft as fixture


class SavedDraftMenuTests(unittest.TestCase):
    def setUp(self):
        self.placement = placement.SourceTests()
        self.placement.setUp()
        self.addCleanup(self.placement.doCleanups)
        self.root = self.placement.root
        self.session = fixture.session()
        self.tester, self.catalogs = fixture.Tester(), fixture.Catalogs()
        self.write_active()
        self.stores = connect_router_manager_files(self.placement.source, root=str(self.root))
        self.directory = self.placement.path(placement.MOUNTS[1]) / DRAFT_DIRECTORY
        DraftSessionFiles(str(self.directory)).create_draft(self.session)
        self.sources = MenuSources(drafts=self.stores.drafts,
            fingerprints=SourceFingerprints(root=str(self.root), read=self.rci),
            geodata=GeoDatabaseFiles(root=str(self.root)), candidate_assets=GeoCandidateFiles(root=str(self.root)),
            geo_catalogs=self.catalogs, installed_xray=self.tester)

    def put(self, path, data):
        p = self.root / path.lstrip('/')
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def write_active(self):
        snap = self.session.candidate.original
        for part in snap.xray_configs.parts:
            self.put(XRAY_CONFIG_DIRECTORY+'/'+part.name, part.content)
        self.put(XKEEN_SETTINGS_PATH, snap.xkeen_settings)
        self.put(XKEEN_INIT_PATH, snap.xkeen_init)
        for name, content in ((XKeenListName.PORT_EXCLUDE, snap.xkeen_port_exclude),
                              (XKeenListName.PORT_PROXYING, snap.xkeen_port_proxying),
                              (XKeenListName.IP_EXCLUDE, snap.xkeen_ip_exclude)):
            self.put(XKEEN_LIST_DIRECTORY+'/'+name.value, content)
        for name, content in fixture.DATA.items():
            self.put(XRAY_ASSET_DIRECTORY+'/'+name, content)

    def rci(self, resource):
        snap = self.session.candidate.original
        if resource is RciResource.POLICIES:
            return snap.keenetic_policies
        if resource is RciResource.HOTSPOT_SETTINGS:
            return snap.keenetic_hotspot_settings.export()
        self.fail('Запрошен несвязанный ресурс RCI.')

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_mode, p.lstat().st_ino,
                p.read_bytes() if p.is_file() and not p.is_symlink() else None) for p in self.root.rglob('*')}

    def assert_private(self, output):
        for marker in (fixture.SECRET, fixture.ID, str(self.root), 'TEST_', *placement.UUIDS,
                       'geoip.dat', 'geosite.dat', *(r.sha256 for r in fixture.REVISIONS)):
            self.assertNotIn(marker, output)

    def run_menu(self, choices, sources=None):
        output, error = io.StringIO(), io.StringIO()
        before = self.snapshot()
        with read_only(), patch.object(entrypoints, 'router_sources', return_value=sources or self.sources):
            code = entrypoints.vpn_menu(['--read-router'], io.StringIO(choices), output, error)
        self.assertEqual(code, 0, error.getvalue())
        self.assertEqual(error.getvalue(), '')
        self.assertEqual(self.snapshot(), before)
        self.assert_private(output.getvalue())
        return output.getvalue()

    def test_full_file_path_from_menu_to_zero_diff_and_two_results(self):
        output = self.run_menu('7\n1\n2\n0\n0\n2\n')
        self.assertIn('Изменений нет: полные снимки совпадают.', output)
        self.assertIn('Статическая проверка:', output)
        self.assertIn('Бинарная проверка установленным Xray:', output)
        self.assertIn('installed_xray_candidate: успешно', output)
        self.assertEqual(len(self.tester.calls), 1)
        self.assertEqual(self.tester.calls[0].parts,
            tuple((p.name, p.content) for p in self.session.candidate.snapshot.xray_configs.parts))

    def test_menu_secret_change_is_visible_without_values(self):
        updated = fixture.session(candidate=fixture.snapshot('TEST_changed_secret'))
        (self.directory/DRAFT_FILE_NAME).write_bytes(encode_draft_session(updated))
        output = self.run_menu('7\n1\n0\n0\n2\n')
        self.assertIn('credentials: изменено', output)
        self.assertNotIn('Изменений нет:', output)

    def test_missing_evidence_and_missing_runner_are_separate(self):
        output = self.run_menu('7\n2\n0\n0\n2\n', replace(self.sources, geo_catalogs=None, installed_xray=None))
        self.assertIn('Итог: неполная', output)
        self.assertIn('geo_categories_unverified', output)
        self.assertIn('Следующий шаг: ' + NEXT_STEP_MESSAGES[NextStepCode.CONSULT_DOCUMENTATION], output)
        self.assertIn('xray_isolation_unavailable', output)
        self.assertFalse(self.tester.calls)

    def test_empty_xray_catalog_shows_separate_static_and_binary_results(self):
        updated = fixture.session(candidate=replace(fixture.snapshot(), xray_configs=XrayConfigSet(())))
        (self.directory/DRAFT_FILE_NAME).write_bytes(encode_draft_session(updated))
        output = self.run_menu('7\n2\n0\n0\n2\n')
        self.assertIn('Статическая проверка:', output)
        self.assertIn('Бинарная проверка установленным Xray:', output)
        self.assertIn('installed_xray_candidate: не проверено, причина candidate_xray_empty', output)
        self.assertNotIn('invalid_command', output)
        self.assertFalse(self.tester.calls)

    def test_binary_structural_limit_does_not_hide_static_result(self):
        updated = fixture.session(candidate=fixture.binary_limit_snapshot())
        (self.directory/DRAFT_FILE_NAME).write_bytes(encode_draft_session(updated))
        output = self.run_menu('7\n2\n0\n0\n2\n')
        self.assertIn('Статическая проверка:\nИтог: успешно', output)
        self.assertIn('installed_xray_candidate: не проверено, причина candidate_binary_input_unsupported', output)
        self.assertNotIn('invalid_command', output)
        self.assertFalse(self.tester.calls)

    def test_changed_native_permit_rejects_diff_without_partial_result(self):
        read = self.sources.fingerprints._read
        def changed(resource):
            value = read(resource)
            if resource is RciResource.POLICIES:
                return {'TEST_policy': {'permit': ['TEST_changed']}}
            return value
        self.sources.fingerprints._read = changed
        output = self.run_menu('7\n1\n0\n0\n2\n')
        self.assertIn('draft_baseline_changed', output)
        self.assertNotIn('Изменения без секретов:', output)

    def test_unreadable_or_missing_full_source_rejects_diff(self):
        (self.root/XKEEN_INIT_PATH.lstrip('/')).unlink()
        output = self.run_menu('7\n1\n0\n0\n2\n')
        self.assertIn('draft_baseline_changed', output)
        self.assertNotIn('Изменения без секретов:', output)

    def test_session_changes_between_inspect_and_execution(self):
        reader = self.stores.drafts.read_draft
        calls = 0
        def changed():
            nonlocal calls
            result = reader()
            calls += 1
            # Первое чтение — шапка, второе — InspectDraft перед действием.
            if calls == 2:
                self.stores.drafts.read_draft = lambda: None
            return result
        self.stores.drafts.read_draft = changed
        output = self.run_menu('7\n1\n0\n0\n')
        self.assertIn('draft_revision_conflict', output)
        self.assertNotIn('Изменений нет:', output)

    def test_disconnected_sources_keep_actions_unavailable(self):
        for sources in (MenuSources(), replace(self.sources, drafts=None), replace(self.sources, fingerprints=None)):
            assembly = assemble_main_menu(sources)
            for number in (1, 2):
                item = assembly.menu.item(7).submenu.item(number)
                self.assertIs(item.reason, UnavailableReason.SOURCE_NOT_CONNECTED)
            self.assertNotIn('draft.diff', assembly.actions)

    def test_unconfirmed_data_explains_both_draft_actions_as_storage_failure(self):
        error = ErrorDetail(ErrorCategory.SOURCE_FAILED, 'storage_placement_unavailable',
                            'Размещение DATA не подтверждено.')
        sources = MenuSources(storage_error=error)
        assembly = assemble_main_menu(sources)
        for number in (1, 2):
            self.assertIs(assembly.menu.item(7).submenu.item(number).reason,
                          UnavailableReason.STORAGE_NOT_CONFIRMED)
        output = self.run_menu('7\n1\n2\n', sources)
        self.assertEqual(output.count('Хранилища не подключены: размещение роли data или выбранные каталоги'), 2)
        self.assertNotIn('Источник чтения роутера не подключён:', output)
        self.assertFalse(self.tester.calls)

    def test_missing_saved_session_is_reported_without_creation(self):
        (self.directory/DRAFT_FILE_NAME).unlink()
        output = self.run_menu('7\n1\n2\n0\n0\n')
        self.assertIn('Сохранённого черновика нет.', output)

    def test_geo_reader_rejects_traversal_symlink_and_size_without_writes(self):
        source = self.sources.candidate_assets
        for name, limit in (('../TEST_secret', 100), ('/TEST_secret', 100), ('geoip.dat', 0),
                            ('geoip.dat', True), ('geoip.dat', 1)):
            with self.subTest(name=name, limit=limit), read_only(), self.assertRaises(RouterReadError):
                source.read_asset(name, limit)
        p = self.root/XRAY_ASSET_DIRECTORY.lstrip('/')/'link.dat'
        p.symlink_to('geoip.dat')
        with read_only(), self.assertRaises(RouterReadError) as caught:
            source.read_asset('link.dat', 100)
        self.assertIs(caught.exception.failure, RouterReadFailure.UNSAFE)

    def test_geo_changed_during_read_never_reaches_runner(self):
        source = self.sources.candidate_assets
        with patch.object(source, 'read_asset', side_effect=RouterReadError(RouterReadFailure.CHANGED)):
            output = self.run_menu('7\n2\n0\n0\n2\n')
        self.assertIn('draft_assets_unavailable', output)
        self.assertFalse(self.tester.calls)

    def test_real_router_composition_connects_existing_executor_lazily_without_running(self):
        from keenvpn.adapters.xray_isolated_port import IsolatedInstalledXray
        with read_only(), patch.object(composition, 'connect_router_manager_files', return_value=self.stores):
            sources = composition.router_sources()
        self.assertIsInstance(sources.fingerprints, SourceFingerprints)
        self.assertIsInstance(sources.candidate_assets, GeoCandidateFiles)
        self.assertIsInstance(sources.installed_xray, IsolatedInstalledXray)
        self.assertIsNone(sources.geo_catalogs)

    def test_unavailable_optional_runner_dependency_preserves_menu(self):
        original = __import__
        def importing(name, *args, **kwargs):
            if name == 'keenvpn.adapters.xray_isolated_port':
                raise ImportError('TEST_private')
            return original(name, *args, **kwargs)
        with read_only(), patch.object(composition, 'connect_router_manager_files', return_value=self.stores), \
                patch('builtins.__import__', side_effect=importing):
            sources = composition.router_sources()
        self.assertIsNone(sources.installed_xray)
        self.assertIs(sources.drafts, self.stores.drafts)


if __name__ == '__main__':
    unittest.main()
