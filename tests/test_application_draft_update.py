"""Сохранение кандидата без пересчёта baseline, утечек и внешних действий."""

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.draft_session import draft_revision_token, InspectDraft, InspectDraftHandler
from keenvpn.application.draft_update import UpdateDraft, UpdateDraftHandler
from keenvpn.application.source_baseline import compare_baseline
from keenvpn.domain.draft_snapshot import prepare_snapshot
from keenvpn.application.ports import DraftSessionStoreError, DraftStoreFailure, StoreReason
from keenvpn.domain.draft_candidate_state import DraftCandidateState, build_draft_candidate, snapshot_document
from keenvpn.domain.draft_session import decode_draft_session, draft_revision, encode_draft_session
from keenvpn.domain.manager_metadata import UnknownFields
from tests.support.in_memory import InMemoryDraftSessionStore
from tests.support.isolation import forbid_external_effects
from tests import test_draft_candidate_state as fixture


class UpdateDraftTests(unittest.TestCase):
    def setUp(self):
        self.original = fixture.snapshot()
        self.candidate = replace(self.original, xkeen_init=b'changed\n')
        self.raw = encode_draft_session(fixture.session())
        self.store = InMemoryDraftSessionStore(self.raw)
        self.handler = UpdateDraftHandler(self.store, operation_ids=lambda: 'test-update')

    def command(self, **fields):
        return UpdateDraft(**(dict(draft_id=fixture.DRAFT_ID,
            expected_revision=draft_revision_token(draft_revision(self.store.content or self.raw)),
            original=self.original, candidate=self.candidate, geo_revisions=fixture.GEO) | fields))

    def run_update(self, command=None, **fields):
        command = self.command(**fields) if command is None else command
        with forbid_external_effects():
            result = self.handler.execute(command)
        public = repr(result) + json.dumps(result.to_dict(), ensure_ascii=False) + repr(command)
        for marker in (fixture.SECRET, 'TEST_policy', 'geoip.dat', 'geosite.dat', 'a'*64, 'b'*64):
            self.assertNotIn(marker, public)
        self.assertIsNone(result.data if not result.succeeded else result.error)
        return result

    def assert_error(self, result, code):
        self.assertFalse(result.succeeded)
        self.assertEqual(result.error.code, code)
        if code != "invalid_command":
            self.assertIsNotNone(result.error.next_step)

    def test_success_preserves_identity_baseline_extra_and_returns_new_token(self):
        result = self.run_update()
        self.assertTrue(result.succeeded, result.error)
        current = decode_draft_session(self.store.content)
        old = decode_draft_session(self.raw).session
        self.assertEqual((current.session.baseline, current.session.extra, current.session.created_at,
                          current.session.draft_id), (old.baseline, old.extra, old.created_at, old.draft_id))
        self.assertEqual(result.data.revision, draft_revision_token(current.revision))
        self.assertNotEqual(result.data.revision, draft_revision_token(draft_revision(self.raw)))
        self.assertEqual(self.store.replace_calls[0][1], draft_revision(self.raw))
        self.assertEqual((self.store.create_calls, self.store.remove_calls, self.store.confirm_calls), ((), (), 0))
        self.assertEqual(snapshot_document(current.session.candidate.snapshot), snapshot_document(self.candidate))
        view = InspectDraftHandler(self.store).execute(InspectDraft()).data.draft
        self.assertEqual(view, result.data)

    def test_second_edit_reuses_original_and_geo_revisions(self):
        self.assertTrue(self.run_update().succeeded)
        state = decode_draft_session(self.store.content).session.candidate
        result = self.run_update(original=None, geo_revisions=None, candidate=self.original)
        self.assertTrue(result.succeeded, result.error)
        new = decode_draft_session(self.store.content).session.candidate
        self.assertEqual(new.export()['original'], state.export()['original'])
        self.assertEqual(new.geo_revisions, fixture.GEO)
        self.assertTrue(self.run_update(original=None, geo_revisions=()).succeeded)
        self.assertEqual(decode_draft_session(self.store.content).session.candidate.geo_revisions, ())

    def test_unchanged_candidate_returns_same_token_after_store_confirmation(self):
        first = self.run_update().data
        second = self.run_update(original=None, geo_revisions=None).data
        self.assertEqual(first, second)
        self.assertEqual(len(self.store.replace_calls), 2)

    def test_stale_token_other_id_and_external_file_edit_do_not_write(self):
        stale = self.command()
        self.assertTrue(self.run_update().succeeded)
        before = self.store.content
        count = len(self.store.replace_calls)
        self.assert_error(self.run_update(stale), 'draft_revision_conflict')
        self.assert_error(self.run_update(draft_id='0000abcd-0000-4000-8000-00000000000e'), 'draft_mismatch')
        command = self.command()
        self.store.content += b'\n'
        before = self.store.content
        self.assert_error(self.run_update(command), 'draft_revision_conflict')
        self.assertEqual(self.store.content, before)
        self.assertEqual(len(self.store.replace_calls), count)

    def test_last_moment_external_edit_is_store_conflict(self):
        external = self.raw + b'\n'
        self.store.before_revision_check = lambda: setattr(self.store, 'content', external)
        result = self.run_update()
        self.assert_error(result, 'draft_revision_conflict')
        self.assertEqual(self.store.content, external)
        self.assertTrue(result.error.conflicts)

    def test_missing_and_corrupt_sessions_are_not_written(self):
        for raw, code in [(None, 'draft_revision_conflict'), (b'{', 'invalid_stored_draft')]:
            self.store.content = raw
            self.assert_error(self.run_update(expected_revision=draft_revision_token(draft_revision(self.raw))), code)
            self.assertEqual(self.store.content, raw)
        self.assertEqual(self.store.replace_calls, [])

    def test_first_edit_requires_full_original_matching_existing_baseline(self):
        for original in (None, replace(self.original, xkeen_init=None),
                         replace(self.original, keenetic_policies={'different': True})):
            code = 'invalid_draft_candidate' if original is None else 'draft_original_mismatch'
            self.assert_error(self.run_update(original=original), code)
        self.assertEqual(self.store.content, self.raw)
        self.assertEqual(self.store.replace_calls, [])

    def test_missing_or_unknown_baseline_is_preserved_and_cannot_be_rebased(self):
        original_session = fixture.session()
        for baseline in (None, replace(original_session.baseline, extra=UnknownFields({'future': fixture.SECRET}))):
            self.store.content = encode_draft_session(replace(original_session, baseline=baseline))
            before = self.store.content
            self.assert_error(self.run_update(), 'draft_original_mismatch')
            self.assertEqual(self.store.content, before)
        self.assertEqual(self.store.replace_calls, [])

    def test_unknown_candidate_records_and_top_level_survive_edit(self):
        values = build_draft_candidate(self.original, self.candidate, fixture.GEO).export()
        values['future'] = fixture.SECRET
        values['snapshot']['future_source'] = {'private': fixture.SECRET}
        state = DraftCandidateState(values)
        self.store.content = encode_draft_session(replace(fixture.session(), candidate=state))
        self.assertTrue(self.run_update(original=None).succeeded)
        after = decode_draft_session(self.store.content).session
        self.assertEqual(after.candidate.export()['future'], fixture.SECRET)
        self.assertEqual(after.candidate.export()['snapshot']['future_source'], values['snapshot']['future_source'])
        self.assertEqual(after.extra, fixture.session().extra)

    def test_bad_command_version_token_or_deleted_field_does_not_read(self):
        for command in (object(), self.command(contract_version=2), self.command(expected_revision='a'*64),
                        self.command(draft_id='invalid')):
            result = self.run_update(command)
            self.assertFalse(result.succeeded)
        for field in ('draft_id', 'expected_revision', 'candidate'):
            command = self.command(); object.__delattr__(command, field)
            self.assert_error(self.run_update(command), 'invalid_command')
        self.assertEqual(self.store.read_calls, 0)

    def test_invalid_payload_and_oversize_do_not_write(self):
        for candidate in (object(), replace(self.original, xkeen_init=b'x'*(1024*1024)),
                          replace(self.original, xkeen_settings=b'{broken')):
            self.assert_error(self.run_update(candidate=candidate), 'invalid_draft_candidate')
        self.assert_error(self.run_update(geo_revisions=['private']), 'invalid_draft_candidate')
        self.assertEqual(self.store.replace_calls, [])
        self.assertEqual(self.store.content, self.raw)

    def test_all_store_failures_are_closed_and_never_success(self):
        for failure in DraftStoreFailure:
            self.store.write_failure = DraftSessionStoreError(failure, reason=fixture.SECRET)
            self.assert_error(self.run_update(), failure.value)
            self.assertEqual(self.store.content, self.raw)
        self.store.write_failure = OSError(fixture.SECRET)
        self.assert_error(self.run_update(), 'draft_store_failed')

    def test_unconfirmed_write_requires_reread_and_current_token(self):
        command = self.command()
        self.store.publish_before_failure = True
        self.store.write_failure = DraftSessionStoreError(DraftStoreFailure.WRITE_UNCONFIRMED, reason=StoreReason.IO_ERROR)
        self.assert_error(self.run_update(command), 'draft_write_unconfirmed')
        self.assertNotEqual(self.store.content, self.raw)
        self.store.write_failure = None
        self.assert_error(self.run_update(command), 'draft_revision_conflict')
        self.assertTrue(self.run_update(original=None).succeeded)

    def test_wrong_store_revision_is_not_success(self):
        original = self.store.replace_draft
        def bad(session, revision):
            original(session, revision)
            return 'a'*64
        self.store.replace_draft = bad
        self.assert_error(self.run_update(), 'invalid_draft_store_result')

    def test_saved_original_is_the_same_snapshot_that_was_checked(self):
        def change_after_check(source, baseline):
            result = compare_baseline(source, baseline)
            self.original.keenetic_policies['TEST_policy']['permit'].append('TEST_late_change')
            return result
        with patch('keenvpn.application.draft_update.compare_baseline', side_effect=change_after_check):
            result = self.run_update()
        self.assertTrue(result.succeeded, result.error)
        saved = decode_draft_session(self.store.content).session
        self.assertIsNone(compare_baseline(prepare_snapshot(saved.candidate.original), saved.baseline))

    def test_existing_original_different_json_type_cannot_pass_as_equal(self):
        for old_value, new_value in ((True, 1), (1, 1.0)):
            old_original = replace(self.original, keenetic_policies={'value': old_value})
            new_original = replace(self.original, keenetic_policies={'value': new_value})
            state = build_draft_candidate(old_original, self.candidate, ())
            inconsistent = replace(fixture.session(new_original), candidate=state)
            self.store.content = encode_draft_session(inconsistent)
            before = self.store.content
            self.assert_error(self.run_update(original=new_original), 'invalid_draft_candidate')
            self.assertEqual(self.store.content, before)
        self.assertEqual(self.store.replace_calls, [])
