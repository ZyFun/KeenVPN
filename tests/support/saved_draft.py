"""Полный искусственный сохранённый кандидат для проверок интеграции."""

from dataclasses import replace
import hashlib
import json

from keenvpn.adapters.geodata_files import geo_inventory_from_files
from keenvpn.application.draft_candidate import GeoCategoryCatalog
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.draft_candidate_state import build_draft_candidate
from keenvpn.domain.draft_session import encode_draft_session
from keenvpn.domain.routing import GeoDatabase, GeoDatabaseKind as Kind
from keenvpn.domain.xray_config import XrayConfigSet
from tests import test_draft_candidate_state as stored_fixture
from tests.support.in_memory import InMemoryDraftSessionStore, InMemoryGeoDatabaseSource, InMemorySourceFingerprints
from tests.test_application_draft_diff import fingerprints
from tests.test_installed_xray import Tester


SECRET = 'TEST_ONLY_SAVED_PASSWORD'
ID = stored_fixture.DRAFT_ID
DATA = {'geoip.dat': b'TEST_BINARY_IP', 'geosite.dat': b'TEST_BINARY_SITE'}
REVISIONS = tuple(GeoDatabase(kind, name, sha256=hashlib.sha256(DATA[name]).hexdigest())
                  for kind, name in ((Kind.GEOIP, 'geoip.dat'), (Kind.GEOSITE, 'geosite.dat')))


def snapshot(password=SECRET):
    document = {'outbounds': [{'protocol': 'freedom', 'tag': 'TEST_out'},
        {'protocol': 'trojan', 'tag': 'TEST_proxy', 'settings': {'servers': [
            {'address': 'vpn.example.test', 'port': 443, 'password': password}]}}],
        'routing': {'rules': [{'ip': ['geoip:TEST_IP'], 'outboundTag': 'TEST_out'},
            {'domain': ['geosite:TEST_SITE'], 'outboundTag': 'TEST_out'},
            {'network': 'tcp,udp', 'outboundTag': 'TEST_out'}]}}
    xray = XrayConfigSet((ConfigDocument('01_TEST_log.json', b'{/* TEST_private */ "log":{}}'),
                         ConfigDocument('02_TEST_proxy.json', json.dumps(document).encode())))
    return replace(stored_fixture.snapshot(), xray_configs=xray,
        xkeen_init=b'#!/bin/sh\n# TEST_private\nproxy_dns="off"\nproxy_router="on"\n',
        xkeen_port_exclude=b'', xkeen_port_proxying=b'')


def session(original=None, candidate=None, revisions=REVISIONS):
    original = snapshot() if original is None else original
    return replace(stored_fixture.session(original), candidate=build_draft_candidate(
        original, original if candidate is None else candidate, revisions))


def binary_limit_snapshot():
    """Допустимый сохранённый JSON за консервативным структурным пределом binary."""
    value = snapshot()
    parts = list(value.xray_configs.parts)
    document = json.loads(parts[-1].content)
    document['unknown_test_values'] = list(range(17000))
    parts[-1] = ConfigDocument(parts[-1].name, json.dumps(document).encode())
    return replace(value, xray_configs=XrayConfigSet(tuple(parts)))


class Assets:
    def __init__(self):
        self.data, self.calls, self.hook = dict(DATA), [], lambda: None

    def read_asset(self, name, limit):
        self.calls.append((name, limit))
        self.hook()
        return self.data[name]


class Catalogs:
    def __init__(self):
        self.values = tuple(GeoCategoryCatalog(db, frozenset({'TEST_IP' if db.kind is Kind.GEOIP else 'TEST_SITE'}))
                            for db in REVISIONS)
        self.calls, self.hook = [], lambda: None

    def read_catalogs(self, revisions):
        self.calls.append(revisions)
        self.hook()
        return self.values


class Inputs:
    def __init__(self):
        self.session = session()
        self.store = InMemoryDraftSessionStore(encode_draft_session(self.session))
        self.fingerprints = InMemorySourceFingerprints()
        for item in fingerprints(self.session.candidate.original):
            self.fingerprints.set_response(item.source, item)
        self.assets, self.catalogs, self.tester = Assets(), Catalogs(), Tester()
        self.geodata = InMemoryGeoDatabaseSource(geo_inventory_from_files(DATA))
