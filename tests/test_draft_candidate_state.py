"""Полнота, совместимость и приватность сохранённого кандидата."""

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.domain.draft_candidate_state import (
    DraftCandidateState, DraftCandidateStateError, build_draft_candidate, rebuild_draft_candidate, snapshot_document,
)
from keenvpn.domain.draft_session import (
    DraftSession, DraftSessionError, DraftSessionErrorCode, decode_draft_session, encode_draft_session,
)
from keenvpn.domain.draft_snapshot import DraftDiffSnapshot
from keenvpn.domain.keenetic_native import KeeneticHotspotSettings
from keenvpn.domain.manager_metadata import UnknownFields
from keenvpn.domain.routing import GeoDatabase, GeoDatabaseKind
from keenvpn.domain.source_baseline import BaselineSource, SourceBaseline
from keenvpn.domain.xray_config import XrayConfigSet
from tests import test_application_draft_diff as fixture


SECRET = 'TEST_ONLY_SAVED_PASSWORD'
DRAFT_ID = '0000abcd-0000-4000-8000-00000000000d'
GEO = (GeoDatabase(GeoDatabaseKind.GEOIP, 'geoip.dat', sha256='a' * 64),
       GeoDatabase(GeoDatabaseKind.GEOSITE, 'geosite.dat', sha256='b' * 64))


def snapshot():
    return DraftDiffSnapshot(
        xray_configs=fixture.xray(('01_log.json', b'{ // comment\n"log": {}}'),
                                 ('02_proxy.json', json.dumps(fixture.proxy(SECRET)).encode())),
        xkeen_settings=b'{"xkeen":{},"unknown":true}', xkeen_init=b'#!/bin/sh\n# \xff\nproxy_dns="on"\n',
        xkeen_port_exclude=b'# note\n53\n', xkeen_port_proxying=b'443\n', xkeen_ip_exclude=b'',
        keenetic_policies={'TEST_policy': {'permit': ['TEST_second', 'TEST_first'], 'unknown': [True, 1]}},
        keenetic_hotspot_settings=KeeneticHotspotSettings({'host': [], 'unknown': {'value': SECRET}}),
    )


def session(original=None):
    original = snapshot() if original is None else original
    return DraftSession(DRAFT_ID, datetime(2026, 11, 8, tzinfo=timezone.utc),
                        UnknownFields({'future': {'secret': SECRET}}), SourceBaseline(fixture.fingerprints(original)))


class CandidateStateTests(unittest.TestCase):
    def setUp(self):
        self.original = snapshot()
        self.candidate = replace(self.original, xkeen_port_exclude=b'54\n',
                                 xray_configs=XrayConfigSet(tuple(reversed(self.original.xray_configs.parts))))
        self.state = build_draft_candidate(self.original, self.candidate, GEO)

    def assert_safe_error(self, call, kind=DraftCandidateStateError):
        with self.assertRaises(kind) as caught:
            call()
        self.assertNotIn(SECRET, repr(caught.exception) + str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    def test_session_roundtrip_preserves_full_bytes_and_native_documents(self):
        raw = encode_draft_session(replace(session(), candidate=self.state))
        stored = decode_draft_session(raw)
        self.assertEqual(encode_draft_session(stored.session), raw)
        self.assertEqual(snapshot_document(stored.session.candidate.original), snapshot_document(self.original))
        self.assertEqual(snapshot_document(stored.session.candidate.snapshot), snapshot_document(self.candidate))
        self.assertEqual(stored.session.candidate.geo_revisions, GEO)
        self.assertEqual(stored.session.candidate.snapshot.xkeen_init, self.original.xkeen_init)
        self.assertEqual([p.name for p in stored.session.candidate.snapshot.xray_configs.parts],
                         ['02_proxy.json', '01_log.json'])

    def test_original_and_candidate_are_independent_private_copies(self):
        self.original.keenetic_policies.clear()
        self.state.snapshot.keenetic_policies.clear()
        exported = self.state.export()
        exported['snapshot']['keenetic_policies'].clear()
        self.assertTrue(self.state.snapshot.keenetic_policies)
        self.assertTrue(self.state.original.keenetic_policies)
        self.assertNotIn(SECRET, repr(self.state) + str(self.state) + repr(replace(session(), candidate=self.state)))
        self.assertNotIn(SECRET, json.dumps(replace(session(), candidate=self.state).to_diagnostic()))

    def test_old_v1_remains_byte_compatible(self):
        old = encode_draft_session(session())
        self.assertNotIn(b'"candidate"', old)
        stored = decode_draft_session(old)
        self.assertIsNone(stored.session.candidate)
        self.assertEqual(encode_draft_session(stored.session), old)

    def test_unknown_fields_and_records_survive_reencoding_and_edit(self):
        values = self.state.export()
        values['unknown'] = {SECRET: [True, 1, None]}
        values['original']['future_source'] = {SECRET: 'original'}
        values['snapshot']['future_source'] = {SECRET: 'candidate'}
        values['geo_revisions']['future_database'] = {SECRET: 'revision'}
        old = DraftCandidateState(values)
        updated = build_draft_candidate(old.original, self.original, (), old)
        result = decode_draft_session(encode_draft_session(replace(session(), candidate=updated))).session
        out = result.candidate.export()
        for name in ('unknown', 'original'):
            self.assertEqual(out[name], values[name])
        self.assertEqual(out['snapshot']['future_source'], values['snapshot']['future_source'])
        self.assertEqual(out['geo_revisions']['future_database'], values['geo_revisions']['future_database'])
        self.assertEqual(result.extra.export(), session().extra.export())

    def test_absent_empty_and_missing_are_distinct(self):
        for source in BaselineSource:
            value = replace(self.original, **{source.value: None})
            state = build_draft_candidate(value, value, ())
            self.assertIsNone(getattr(state.snapshot, source.value))
            values = state.export()
            del values['snapshot'][source.value]
            self.assert_safe_error(lambda: DraftCandidateState(values))
        self.assertEqual(self.state.original.xkeen_ip_exclude, b'')
        empty = replace(self.original, xray_configs=XrayConfigSet(()))
        self.assertEqual(build_draft_candidate(empty, empty, ()).snapshot.xray_configs.parts, ())

    def test_bad_known_sections_are_not_treated_as_unknown(self):
        cases = []
        for field in ('original', 'snapshot', 'geo_revisions'):
            for value in (None, [], SECRET):
                doc = self.state.export(); doc[field] = value; cases.append(doc)
            doc = self.state.export(); del doc[field]; cases.append(doc)
        for value in ('!', 'Zg=', 'Zh==', ' Zg==', 1, True):
            doc = self.state.export(); doc['snapshot']['xkeen_init'] = value; cases.append(doc)
        doc = self.state.export(); doc['snapshot']['xray_configs'].append(doc['snapshot']['xray_configs'][0]); cases.append(doc)
        doc = self.state.export(); doc['original']['xray_configs'].reverse(); cases.append(doc)
        doc = self.state.export(); doc['snapshot']['xray_configs'][0][0] = '../secret.json'; cases.append(doc)
        doc = self.state.export(); doc['snapshot']['xkeen_port_exclude'] = '/w=='; cases.append(doc)
        doc = self.state.export(); doc['geo_revisions']['geoip']['geoip.dat'] = SECRET; cases.append(doc)
        for index, doc in enumerate(cases):
            with self.subTest(index=index):
                self.assert_safe_error(lambda: DraftCandidateState(doc))

    def test_invalid_candidate_maps_to_closed_session_error(self):
        for value in (None, {}, SECRET, {'original': SECRET}):
            doc = json.loads(encode_draft_session(session())); doc['candidate'] = value
            error = self.assert_safe_error(lambda: decode_draft_session(json.dumps(doc).encode()), DraftSessionError)
            self.assertIs(error.code, DraftSessionErrorCode.CANDIDATE)
            self.assertEqual(error.field, 'candidate')

    def test_tampered_model_and_exact_types_are_revalidated(self):
        class Text(str):
            pass
        class Trap:
            def export(self):
                raise AssertionError(SECRET)
        for value in (None, Trap(), Text(SECRET)):
            state = DraftCandidateState(self.state.export())
            object.__setattr__(state, '_fields', value)
            self.assert_safe_error(lambda: rebuild_draft_candidate(state))
            error = self.assert_safe_error(lambda: encode_draft_session(replace(session(), candidate=state)),
                                           DraftSessionError)
            self.assertIs(error.code, DraftSessionErrorCode.CANDIDATE)
        doc = self.state.export(); doc['snapshot']['xkeen_init'] = Text('')
        self.assert_safe_error(lambda: DraftCandidateState(doc))

    def test_full_session_limit_and_nested_unknown_depth_are_enforced(self):
        huge = replace(self.original, xkeen_init=b'x' * (1024 * 1024))
        state = build_draft_candidate(self.original, huge, ())
        error = self.assert_safe_error(lambda: encode_draft_session(replace(session(), candidate=state)), DraftSessionError)
        self.assertIs(error.code, DraftSessionErrorCode.CONTENT)
        deep = {}
        for _ in range(70):
            deep = {'unknown': deep}
        doc = self.state.export(); doc['unknown'] = deep
        self.assert_safe_error(lambda: DraftCandidateState(doc))

    def test_geo_revisions_validate_exact_types_duplicates_and_hashes(self):
        broken = []
        for name, value in [('kind', 'geoip'), ('reference', '../geoip.dat'), ('sha256', 'A'*64)]:
            item = GeoDatabase(GeoDatabaseKind.GEOIP, 'geoip.dat', sha256='a'*64)
            object.__setattr__(item, name, value)
            broken.append((item,))
        for revisions in ([*GEO], (GEO[0], GEO[0]), *broken):
            self.assert_safe_error(lambda: build_draft_candidate(self.original, self.candidate, revisions))

    def test_edit_cannot_replace_original(self):
        changed = replace(self.original, xkeen_init=b'different')
        self.assert_safe_error(lambda: build_draft_candidate(changed, self.candidate, GEO, self.state))

    def test_replacing_original_distinguishes_json_scalar_types(self):
        for first, second in ((True, 1), (1, 1.0)):
            old = replace(self.original, keenetic_policies={'value': first})
            new = replace(self.original, keenetic_policies={'value': second})
            state = build_draft_candidate(old, self.candidate, ())
            self.assert_safe_error(lambda: build_draft_candidate(new, self.candidate, (), state))
