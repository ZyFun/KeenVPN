"""Сохранённые полные входы, ревизии и независимые проверки без внешних действий."""

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.geodata_files import geo_inventory_from_files
from keenvpn.application.contract import CheckStatus, NextStepCode
from keenvpn.application.draft_session import draft_revision_token
from keenvpn.application.ports import RouterReadError, RouterReadFailure
from keenvpn.application.saved_draft import (
    CompareSavedDraft, CompareSavedDraftHandler, CheckSavedDraft, CheckSavedDraftHandler,
)
from keenvpn.application.xray_candidate import CheckInstalledXrayHandler, XrayTestOutcome as Outcome
from keenvpn.domain.draft_candidate_state import build_draft_candidate
from keenvpn.domain.draft_session import draft_revision, encode_draft_session
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot
from keenvpn.domain.source_baseline import BaselineSource, FingerprintState, SourceFingerprint
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.interfaces.cli.draft_presenters import present_draft_diff, present_saved_draft_check
from tests.support.isolation import forbid_external_effects
from tests.support.privacy import reachable
from tests.support import saved_draft as fixture


class SavedDraftTests(unittest.TestCase):
    def setUp(self):
        self.inputs = fixture.Inputs()
        self.store = self.inputs.store

    def command(self, cls=CheckSavedDraft, **changes):
        return cls(**(dict(draft_id=fixture.ID,
            expected_revision=draft_revision_token(draft_revision(self.store.content))) | changes))

    def handler(self, cls=CheckSavedDraftHandler, **changes):
        if cls is CompareSavedDraftHandler:
            return cls(self.store, self.inputs.fingerprints, operation_ids=lambda: 'test-saved')
        kwargs = dict(geodata=self.inputs.geodata, assets=self.inputs.assets,
                      catalogs=self.inputs.catalogs, tester=self.inputs.tester)
        return cls(self.store, self.inputs.fingerprints, **(kwargs | changes), operation_ids=lambda: 'test-saved')

    def execute(self, command=None, **sources):
        command = self.command() if command is None else command
        cls = CompareSavedDraftHandler if type(command) is CompareSavedDraft else CheckSavedDraftHandler
        with forbid_external_effects():
            result = self.handler(cls, **sources).execute(command)
        public = repr(result) + json.dumps(result.to_dict(), ensure_ascii=False) + repr(command)
        if result.succeeded:
            public += '\n'.join((present_draft_diff if cls is CompareSavedDraftHandler else present_saved_draft_check)(result.data))
        for marker in (fixture.SECRET, fixture.ID, 'TEST_', 'geoip.dat', 'geosite.dat',
                       *(r.sha256 for r in fixture.REVISIONS)):
            self.assertNotIn(marker, public)
        self.assertFalse(any(isinstance(v, (bytes, BaseException, DraftDiffSnapshot)) for v in reachable(result)))
        self.assertFalse(self.store.create_calls or self.store.remove_calls or self.store.replace_calls or self.store.confirm_calls)
        return result

    def update(self, *, original=None, candidate=None, revisions=fixture.REVISIONS):
        state = self.inputs.session.candidate
        state = build_draft_candidate(state.original if original is None else original,
            state.snapshot if candidate is None else candidate, revisions)
        self.store.content = encode_draft_session(replace(self.inputs.session, candidate=state))

    def test_same_candidate_bytes_and_expected_revisions_reach_both_checks(self):
        before = self.store.content
        result = self.execute()
        self.assertTrue(result.succeeded, result.error)
        self.assertEqual(result.data.static.outcome, 'passed')
        self.assertIs(result.data.binary.status, CheckStatus.PASSED)
        self.assertEqual(self.inputs.catalogs.calls, [fixture.REVISIONS])
        request, = self.inputs.tester.calls
        self.assertEqual(request.parts, tuple((p.name, p.content) for p in self.inputs.session.candidate.snapshot.xray_configs.parts))
        self.assertEqual({(a.kind, a.name, a.sha256) for a in request.assets},
                         {(r.kind, r.reference, r.sha256) for r in fixture.REVISIONS})
        self.assertEqual(self.store.content, before)

    def test_zero_secret_only_and_part_order_diff_are_distinct(self):
        result = self.execute(self.command(CompareSavedDraft))
        self.assertEqual(result.data.entries, ())
        self.update(candidate=fixture.snapshot('TEST_changed_password'))
        result = self.execute(self.command(CompareSavedDraft))
        self.assertEqual([(e.area, e.operation.value) for e in result.data.entries], [('credentials', 'changed')])
        original = fixture.snapshot()
        self.update(candidate=replace(original, xray_configs=XrayConfigSet(tuple(reversed(original.xray_configs.parts)))))
        result = self.execute(self.command(CompareSavedDraft))
        self.assertTrue(any(e.area == 'part' and e.operation.value == 'reordered' for e in result.data.entries))

    def test_all_eight_sources_and_full_native_permit_are_compared(self):
        old = fixture.snapshot()
        new = replace(fixture.snapshot('TEST_changed_password'), xkeen_settings=b'{"changed":true}',
            xkeen_init=old.xkeen_init+b'# changed\n', xkeen_port_exclude=b'53\n', xkeen_port_proxying=b'443\n',
            xkeen_ip_exclude=b'198.51.100.1\n', keenetic_policies={'TEST_policy': {'permit': ['TEST_first']}},
            keenetic_hotspot_settings=type(old.keenetic_hotspot_settings)({'host': [], 'unknown': False}))
        self.update(candidate=new)
        result = self.execute(self.command(CompareSavedDraft))
        self.assertEqual({e.source for e in result.data.entries}, set(BaselineSource))
        self.assertTrue(any(e.area == 'permit' for e in result.data.entries))

    def test_old_v1_without_candidate_does_not_invent_full_snapshots(self):
        self.store.content = encode_draft_session(replace(self.inputs.session, candidate=None))
        for cls in (CheckSavedDraft, CompareSavedDraft):
            result = self.execute(self.command(cls))
            self.assertEqual(result.error.code, 'draft_candidate_missing')
            self.assertIsNone(result.data)

    def test_missing_full_source_corrupt_file_has_no_partial_diff(self):
        raw = json.loads(self.store.content)
        del raw['candidate']['original']['xkeen_init']
        self.store.content = json.dumps(raw).encode()
        result = self.execute(self.command(CompareSavedDraft))
        self.assertEqual(result.error.code, 'invalid_stored_draft')
        self.assertIsNone(result.data)

    def test_wrong_original_live_source_and_session_conflicts_are_distinct(self):
        self.update(original=replace(fixture.snapshot(), xkeen_init=b'# forged\n'))
        for cls in (CheckSavedDraft, CompareSavedDraft):
            self.assertEqual(self.execute(self.command(cls)).error.code, 'diff_original_mismatch')
        self.inputs.fingerprints.set_response(BaselineSource.XKEEN_INIT,
            SourceFingerprint(BaselineSource.XKEEN_INIT, FingerprintState.ABSENT))
        self.assertEqual(self.execute(self.command(CompareSavedDraft)).error.code, 'draft_baseline_changed')
        stale = self.command(CompareSavedDraft)
        self.store.content += b'\n'
        self.assertEqual(self.execute(stale).error.code, 'draft_revision_conflict')

    def test_stale_token_foreign_id_and_lost_session_never_run_xray(self):
        for cls in (CheckSavedDraft, CompareSavedDraft):
            self.assertEqual(self.execute(self.command(cls, expected_revision='0'*32)).error.code, 'draft_revision_conflict')
            self.assertEqual(self.execute(self.command(cls, draft_id='0000abcd-0000-4000-8000-00000000000e')).error.code, 'draft_mismatch')
        command = self.command()
        self.store.content = None
        self.assertEqual(self.execute(command).error.code, 'draft_revision_conflict')
        self.assertFalse(self.inputs.tester.calls)

    def test_failure_of_any_managed_source_discards_whole_report(self):
        for source in BaselineSource:
            previous = self.inputs.fingerprints.current_fingerprint(source)
            self.inputs.fingerprints.set_response(source, RouterReadError(RouterReadFailure.IO_ERROR))
            for cls in (CheckSavedDraft, CompareSavedDraft):
                result = self.execute(self.command(cls))
                self.assertEqual(result.error.code, 'draft_baseline_unavailable')
                self.assertIsNone(result.data)
            self.inputs.fingerprints.set_response(source, previous)
        self.assertFalse(self.inputs.tester.calls)

    def test_no_catalog_is_incomplete_even_with_successful_binary_double(self):
        result = self.execute(catalogs=None)
        self.assertEqual(result.data.static.outcome, 'incomplete')
        self.assertIs(result.data.static.next_step.code, NextStepCode.CONSULT_DOCUMENTATION)
        self.assertIn('geo_categories_unverified', [c.reason for c in result.data.static.checks.items])
        self.assertIs(result.data.binary.status, CheckStatus.PASSED)

    def test_unrelated_revision_file_or_kind_cannot_supply_catalog_evidence(self):
        original = self.inputs.catalogs.values
        db = original[0].database
        for replacement in (replace(db, sha256='a'*64), replace(db, reference='other.dat'),
                            replace(db, kind=fixture.Kind.GEOSITE)):
            self.inputs.catalogs.values = (replace(original[0], database=replacement), original[1])
            self.assertEqual(self.execute().data.static.outcome, 'incomplete')

    def test_geo_changed_is_not_rebased_to_new_content(self):
        self.inputs.assets.data['geoip.dat'] = b'TEST_CHANGED'
        self.inputs.geodata.outcome = geo_inventory_from_files(self.inputs.assets.data)
        result = self.execute()
        self.assertEqual(result.data.static.outcome, 'failed')
        self.assertEqual(result.data.binary.reason, 'candidate_asset_digest')
        self.assertFalse(self.inputs.tester.calls)

    def test_missing_expected_revision_blocks_binary_without_fabricating_sha(self):
        self.update(revisions=())
        result = self.execute()
        self.assertEqual(result.data.binary.reason, 'geo_revision_unknown')
        self.assertFalse(self.inputs.assets.calls or self.inputs.tester.calls)

    def test_unused_expected_file_does_not_become_binary_dependency(self):
        self.update(revisions=(*fixture.REVISIONS, replace(fixture.REVISIONS[0], reference='other.dat')))
        self.assertIs(self.execute().data.binary.status, CheckStatus.PASSED)
        self.assertEqual({n for n, _ in self.inputs.assets.calls}, set(fixture.DATA))

    def test_absent_runner_keeps_static_success_separate(self):
        result = self.execute(tester=None)
        self.assertEqual(result.data.static.outcome, 'passed')
        self.assertEqual(result.data.binary_error.reason, 'xray_isolation_unavailable')
        self.assertIsNone(result.data.binary)

    def test_actual_runner_outcomes_are_forwarded_without_invented_success(self):
        for outcome in Outcome:
            self.inputs.tester.outcome = outcome
            result = self.execute()
            if outcome is Outcome.PASSED:
                self.assertIs(result.data.binary.status, CheckStatus.PASSED)
            elif outcome in (Outcome.REJECTED, Outcome.UNSUPPORTED):
                self.assertEqual(result.data.binary.reason, outcome.value)
            else:
                self.assertEqual(result.data.binary_error.reason, outcome.value)
                self.assertIsNone(result.data.binary)

    def test_empty_xray_catalog_keeps_static_report_without_binary_run(self):
        self.update(candidate=replace(fixture.snapshot(), xray_configs=XrayConfigSet(())))
        self.assertTrue(self.execute(self.command(CompareSavedDraft)).succeeded)
        result = self.execute()
        self.assertTrue(result.succeeded, result.error)
        self.assertIsNotNone(result.data.static)
        self.assertIs(result.data.binary.status, CheckStatus.NOT_CHECKED)
        self.assertEqual(result.data.binary.reason, 'candidate_xray_empty')
        self.assertFalse(self.inputs.assets.calls or self.inputs.tester.calls)

    def test_binary_structural_limit_keeps_static_report_and_strict_runner_contract(self):
        self.update(candidate=fixture.binary_limit_snapshot())
        result = self.execute()
        self.assertTrue(result.succeeded, result.error)
        self.assertEqual(result.data.static.outcome, 'passed')
        self.assertIs(result.data.binary.status, CheckStatus.NOT_CHECKED)
        self.assertEqual(result.data.binary.reason, 'candidate_binary_input_unsupported')
        self.assertFalse(self.inputs.tester.calls)

    def test_conflict_after_unsupported_binary_input_discards_static_report(self):
        self.update(candidate=fixture.binary_limit_snapshot())
        execute = CheckInstalledXrayHandler.execute
        def rejected_then_changed(handler, command):
            result = execute(handler, command)
            self.assertEqual(result.error.code, 'invalid_command')
            self.store.content += b'\n'
            return result
        with patch.object(CheckInstalledXrayHandler, 'execute', rejected_then_changed):
            result = self.execute()
        self.assertEqual(result.error.code, 'draft_revision_conflict')
        self.assertIsNone(result.data)
        self.assertFalse(self.inputs.tester.calls)

    def test_asset_failure_has_safe_reason_and_no_partial_binary_run(self):
        for error in (OSError(fixture.SECRET), RouterReadError(RouterReadFailure.CHANGED)):
            self.inputs.assets.hook = lambda: (_ for _ in ()).throw(error)
            result = self.execute()
            self.assertEqual(result.data.binary_error.code, 'draft_assets_unavailable')
            self.assertFalse(self.inputs.tester.calls)

    def test_catalog_failure_does_not_claim_static_success(self):
        self.inputs.catalogs.hook = lambda: (_ for _ in ()).throw(OSError(fixture.SECRET))
        result = self.execute()
        self.assertEqual(result.data.static_error.code, 'draft_catalogs_unavailable')
        self.assertIs(result.data.binary.status, CheckStatus.PASSED)

    def test_change_during_catalog_read_discards_static_and_prevents_binary(self):
        self.inputs.catalogs.hook = lambda: setattr(self.store, 'content', self.store.content+b'\n')
        result = self.execute()
        self.assertEqual(result.error.code, 'draft_revision_conflict')
        self.assertIsNone(result.data)
        self.assertFalse(self.inputs.tester.calls)

    def test_change_during_asset_read_prevents_binary_and_partial_report(self):
        self.inputs.assets.hook = lambda: self.inputs.fingerprints.set_response(BaselineSource.XKEEN_INIT,
            SourceFingerprint(BaselineSource.XKEEN_INIT, FingerprintState.ABSENT))
        result = self.execute()
        self.assertEqual(result.error.code, 'draft_baseline_changed')
        self.assertIsNone(result.data)
        self.assertFalse(self.inputs.tester.calls)

    def test_change_during_runner_discards_even_binary_passed(self):
        self.inputs.tester.hook = lambda: setattr(self.store, 'content', None)
        result = self.execute()
        self.assertEqual(result.error.code, 'draft_revision_conflict')
        self.assertIsNone(result.data)

    def test_invalid_and_damaged_commands_are_safe_before_reading(self):
        for cls, handler in ((CheckSavedDraft, CheckSavedDraftHandler), (CompareSavedDraft, CompareSavedDraftHandler)):
            bad = self.command(cls)
            object.__delattr__(bad, 'draft_id')
            for command in (None, bad, self.command(cls, expected_revision='TEST_bad')):
                with forbid_external_effects():
                    result = self.handler(handler).execute(command)
                self.assertEqual(result.error.code, 'invalid_command')
        self.assertEqual(self.store.read_calls, 0)


if __name__ == '__main__':
    unittest.main()
