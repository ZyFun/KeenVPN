"""Нулевая разница и идемпотентность повторного импорта существующей установки.

Первое подключение менеджера здесь — последовательное выполнение трёх
существующих сценариев на одних источниках: `InspectInstallation`,
`ImportRoutingScheme` и `ImportStoragePlacement`. Источники — обезличенный снимок
через управляемые адаптеры в памяти либо копия его файлов во временном каталоге
по путям роутера; хранилище метаданных — в памяти либо настоящий
`ManagerMetadataFiles`. Портов записи active configs у сценариев нет, поэтому
отсутствие записи доказывается хешами и числом обращений к источникам, запретом
файловых, сетевых и процессных вызовов и снимком всего дерева файлов до и после.
Роутер, Xray, XKeen и сеть не используются; успех не подтверждает работу VPN,
DNS или Pritunl.
"""

from collections import Counter
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from typing import NamedTuple
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.geodata_files import XRAY_ASSET_DIRECTORY, geo_inventory_from_files
from keenvpn.adapters.keenetic_rci import (
    HOTSPOT_RUNTIME_RESOURCE, HOTSPOT_SETTINGS_RESOURCE, POLICIES_RESOURCE, REGISTRATIONS_RESOURCE,
    hotspot_runtime_from_rci, hotspot_settings_from_rci, policies_from_rci, registrations_from_rci,
)
from keenvpn.adapters.manager_metadata_files import METADATA_FILE_NAME, PROTECTED_DIRECTORIES, ManagerMetadataFiles
from keenvpn.adapters.xkeen_files import (
    XKEEN_INIT_PATH, XKEEN_LIST_DIRECTORY, XKEEN_SETTINGS_PATH, xkeen_init_from_bytes, xkeen_list_from_bytes,
    xkeen_settings_from_bytes,
)
from keenvpn.adapters.xray_configs import XRAY_CONFIG_DIRECTORY, xray_config_from_files
from keenvpn.application.contract import ErrorCategory
from keenvpn.application.installation import InspectInstallation, InspectInstallationHandler
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler
from keenvpn.application.manager_metadata import ImportStoragePlacement, ImportStoragePlacementHandler
from keenvpn.application.ports import MetadataStoreFailure, MetadataStoreReason
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler
from keenvpn.domain.geodata import GEOIP_FILE_NAME
from keenvpn.domain.manager_metadata import (
    ManagerMetadata, StorageVariant, TrackedValue, UnknownFields, ValueState, decode_manager_metadata,
    encode_manager_metadata, metadata_revision,
)
from keenvpn.domain.xkeen_config import XKeenListName
from tests.support.in_memory import InMemoryManagerMetadataStore, InMemoryStoragePlacementSource, InMemoryXrayProcessSource
from tests.support.isolation import forbid_external_effects
from tests.support.snapshot import (
    SNAPSHOT_ROOT, SYNTHETIC_GEOIP_SIZE, SYNTHETIC_HISTORY_RETENTION, SYNTHETIC_HISTORY_SIZE, SYNTHETIC_STORAGE_ID,
    SYNTHETIC_STORAGE_ROOT, load_keenetic_snapshot, load_xkeen_snapshot, load_xray_snapshot_files,
    snapshot_installation_sources, synthetic_storage_placement, synthetic_xray_process,
)


KNOWN = ValueState.KNOWN
LIST_NAMES = (XKeenListName.PORT_EXCLUDE, XKeenListName.PORT_PROXYING, XKeenListName.IP_EXCLUDE)
OTHER_STORAGE_ID = "0000abcd-0000-4000-8000-000000000067"
FUTURE_FIELDS = {
    "future-section": {"rules": [{"id": 1, "enabled": True}], "nested": {"value": 1.5}},
    "": "пустое имя", "Storage": {"state": "known"}, "flag": True, "count": 1,
}
"""Неизвестные поля верхнего уровня, которые мог записать будущий менеджер."""
TREE_KEENETIC = "keenetic/rci.json"
"""Ответы RCI снимка одним файлом: заменитель транспорта RCI только для теста дерева."""
METADATA_PARENT = "manager-state"
METADATA_DIRECTORY = f"{METADATA_PARENT}/keenvpn"
METADATA_FILE = f"{METADATA_DIRECTORY}/{METADATA_FILE_NAME}"


def reads(runs: int) -> tuple:
    """Обращения к источникам снимка за `runs` запусков.

    Keenetic, геобазы и процесс читает только чтение установки; источники
    Xray и XKeen — чтение установки и импорт правил, по одному разу каждый.
    """
    return ((runs,) * 4, (2 * runs, 2 * runs, 2 * runs, LIST_NAMES * (2 * runs)), runs, runs)


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def digest(value: object) -> str:
    """SHA-256 канонического JSON: при расхождении в сообщение попадает хеш, а не данные снимка."""
    return sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def active_state(sources) -> dict[str, object]:
    """Прочитать через порты всё, что сценарии только читают, и свести к хешам.

    Части Xray, `xkeen.json` и списки — по исходным байтам: и сохранённый,
    и заново вычисленный SHA-256. Init — присваивания как написаны, Keenetic —
    канонические JSON-снимки, геобазы и процесс — все поля наблюдения.
    """
    keenetic, proxy = sources.keenetic, sources.proxy
    xray = proxy.xray.current_xray_config()
    settings = proxy.settings.current_xkeen_settings()
    init = proxy.init.current_xkeen_init()
    geodata = sources.geodata.current_geo_databases()
    process = sources.process.current_xray_process()
    return {
        "policies": digest([[item.policy_id, item.description] for item in keenetic.policies.current_policies().policies]),
        "hotspot": digest(keenetic.hotspot.current_hotspot_settings().export()),
        "registrations": digest(keenetic.registrations.current_registrations().export()),
        "runtime": digest(keenetic.runtime.current_hotspot_runtime().export()),
        "xray": [(part.name, part.sha256, sha256(part.content)) for part in xray.parts],
        "xkeen_settings": (settings.document.sha256, sha256(settings.document.content)),
        "init": digest([[item.name, item.raw, item.line_number, item.indented] for item in init.assignments]),
        "lists": [
            (name.value, sha256(proxy.lists.current_xkeen_list(name).text.encode("utf-8"))) for name in LIST_NAMES
        ],
        "geodata": digest([
            [item.name, item.present, item.size, item.sha256, item.source, item.version] for item in geodata.files
        ]),
        "process": (process.pids, process.ready_marker),
    }


def manifest_xray_hashes() -> dict[str, str]:
    """SHA-256 частей Xray из manifest обезличенного снимка."""
    manifest = json.loads((SNAPSHOT_ROOT / "manifest.json").read_text(encoding="utf-8"))
    return {name.removeprefix("xray/"): value for name, value in manifest["files"].items() if name.startswith("xray/")}


class FirstConnection:
    """Три существующих сценария первого подключения в фиксированном порядке на общих портах."""

    def __init__(self, keenetic, proxy, geodata, process, placement, store) -> None:
        options = {"operation_ids": lambda: "test-operation"}
        proxy_handler = InspectProxyConfigHandler(*proxy, **options)
        self.installation = InspectInstallationHandler(
            InspectKeeneticStateHandler(*keenetic, **options), proxy_handler, geodata, process, **options,
        )
        self.routing = ImportRoutingSchemeHandler(proxy_handler, **options)
        self.placement = ImportStoragePlacementHandler(placement, store, **options)

    def run(self) -> tuple:
        return (
            self.installation.execute(InspectInstallation()),
            self.routing.execute(ImportRoutingScheme()),
            self.placement.execute(ImportStoragePlacement()),
        )


def snapshot_flow(sources, placement, store) -> FirstConnection:
    keenetic, proxy = sources.keenetic, sources.proxy
    return FirstConnection(
        (keenetic.policies, keenetic.hotspot, keenetic.registrations, keenetic.runtime),
        (proxy.xray, proxy.settings, proxy.init, proxy.lists), sources.geodata, sources.process, placement, store,
    )


def views(results) -> tuple:
    """Безопасные представления запуска без идентификатора операции."""
    return tuple(None if result.data is None else result.data.to_dict() for result in results)


def canonical_storage(metadata: ManagerMetadata) -> bytes:
    """Канонические байты раздела размещения без посторонних полей верхнего уровня."""
    return encode_manager_metadata(ManagerMetadata(metadata.storage))


class FlowAssertions(unittest.TestCase):
    def assert_read_succeeded(self, results):
        installation, routing, _ = results
        self.assertEqual((installation.succeeded, routing.succeeded), (True, True))

    def assert_mismatch(self, results):
        self.assert_read_succeeded(results)
        error = results[2].error
        self.assertFalse(results[2].succeeded)
        self.assertEqual(
            (error.category, error.code, error.reason),
            (ErrorCategory.UNSUPPORTED, "storage_placement_mismatch", None),
        )


class FirstConnectionInMemoryTests(FlowAssertions):
    """Снимок через адаптеры в памяти и хранилище метаданных в памяти."""

    def setUp(self):
        self.sources = snapshot_installation_sources()
        self.placement = InMemoryStoragePlacementSource(synthetic_storage_placement())
        self.store = InMemoryManagerMetadataStore()
        self.flow = snapshot_flow(self.sources, self.placement, self.store)
        self.expected_state = active_state(snapshot_installation_sources())

    def assert_active_state_unchanged(self):
        # Отдельное чтение после сценариев: число их обращений к источникам уже проверено.
        self.assertEqual(active_state(self.sources), self.expected_state)

    def test_first_connection_writes_only_manager_metadata(self):
        with forbid_external_effects():
            results = self.flow.run()
        self.assert_read_succeeded(results)
        self.assertTrue(results[2].succeeded)
        self.assertEqual(results[2].data.outcome, "created")
        self.assertEqual(self.store.content, encode_manager_metadata(ManagerMetadata(synthetic_storage_placement())))
        self.assertEqual([call.expected_revision for call in self.store.write_calls], [None])
        self.assertEqual((self.store.read_calls, self.store.publications, self.placement.calls), (1, 1, 1))
        self.assertEqual(self.sources.calls, reads(1))
        self.assert_active_state_unchanged()
        self.assertEqual(
            {name: stored for name, stored, _ in self.expected_state["xray"]}, manifest_xray_hashes(),
        )
        self.assertTrue(all(stored == actual for _, stored, actual in self.expected_state["xray"]))
        text = json.dumps(views(results), ensure_ascii=False)
        for marker in (SYNTHETIC_STORAGE_ID, SYNTHETIC_STORAGE_ROOT, metadata_revision(self.store.content)):
            self.assertNotIn(marker, text)

    def test_repeated_imports_change_nothing_and_give_same_views(self):
        first = self.flow.run()
        content = self.store.content
        with forbid_external_effects():
            repeats = [self.flow.run() for _ in range(2)]
        for results in repeats:
            self.assertEqual(views(results)[:2], views(first)[:2])
            self.assertEqual(results[2].data.outcome, "unchanged")
            self.assertEqual(results[2].data.metadata, first[2].data.metadata)
        self.assertIs(self.store.content, content)
        self.assertEqual(metadata_revision(self.store.content), metadata_revision(content))
        self.assertEqual(
            (len(self.store.write_calls), self.store.publications, self.store.read_calls, self.placement.calls),
            (1, 1, 3, 3),
        )
        self.assertEqual(self.sources.calls, reads(3))
        self.assert_active_state_unchanged()

    def test_existing_metadata_keeps_unknown_fields_and_is_written_once(self):
        preset = encode_manager_metadata(ManagerMetadata(None, UnknownFields(FUTURE_FIELDS)))
        self.store.content = preset
        reference = snapshot_flow(
            snapshot_installation_sources(), InMemoryStoragePlacementSource(synthetic_storage_placement()),
            InMemoryManagerMetadataStore(),
        ).run()
        with forbid_external_effects():
            runs = [self.flow.run() for _ in range(3)]
        self.assertEqual([results[2].data.outcome for results in runs], ["created", "unchanged", "unchanged"])
        self.assertEqual([call.expected_revision for call in self.store.write_calls], [metadata_revision(preset)])
        written = decode_manager_metadata(self.store.content).metadata
        self.assertEqual(written.extra.export(), FUTURE_FIELDS)
        self.assertEqual(written.extra.names, tuple(FUTURE_FIELDS))
        self.assertIs(type(written.extra.export()["flag"]), bool)
        self.assertEqual(canonical_storage(written), canonical_storage(ManagerMetadata(synthetic_storage_placement())))
        # Состояние собственных метаданных не влияет на прочитанную установку и правила.
        for results in runs:
            self.assertEqual(views(results)[:2], views(reference)[:2])
        self.assertEqual(runs[0][2].data.metadata.unknown_field_count, len(FUTURE_FIELDS))
        self.assertEqual(self.sources.calls, reads(3))
        self.assert_active_state_unchanged()

    def test_placement_and_limits_are_stored_as_detected_and_kept(self):
        runs = [self.flow.run() for _ in range(3)]
        storage = decode_manager_metadata(self.store.content).metadata.storage
        self.assertEqual((storage.variant.state, storage.variant.value), (KNOWN, StorageVariant.SIMPLE))
        self.assertIs(type(storage.variant.value), StorageVariant)
        roles = (storage.roles.data, storage.roles.history, storage.roles.backups)
        for location, name in zip(roles, ("keenvpn-data", "keenvpn-history", "keenvpn-backups")):
            with self.subTest(name):
                self.assertEqual(
                    (location.state, location.storage_id.state, location.storage_id.value, location.path.state,
                     location.path.value),
                    (KNOWN, KNOWN, SYNTHETIC_STORAGE_ID, KNOWN, f"{SYNTHETIC_STORAGE_ROOT}/{name}"),
                )
                self.assertIs(location.verified, True)
        limits = storage.history_limits
        self.assertEqual(
            (limits.size_bytes.state, limits.size_bytes.value, limits.retention_seconds.state,
             limits.retention_seconds.value),
            (KNOWN, SYNTHETIC_HISTORY_SIZE, KNOWN, SYNTHETIC_HISTORY_RETENTION),
        )
        self.assertEqual((type(limits.size_bytes.value), type(limits.retention_seconds.value)), (int, int))
        self.assertEqual(len(self.store.write_calls), 1)
        for results in runs:
            self.assertEqual(results[2].data.metadata.to_dict()["storage"]["history_limits"], {
                "size_state": "known", "size_bytes": SYNTHETIC_HISTORY_SIZE,
                "retention_state": "known", "retention_seconds": SYNTHETIC_HISTORY_RETENTION,
            })


class TreeEntry(NamedTuple):
    """Объект дерева без времени доступа: чтение файлов его не меняет."""

    kind: int
    mode: int
    inode: int
    mtime_ns: int
    size: int | None
    sha256: str | None


def tree_state(root: Path) -> dict[str, TreeEntry]:
    """Снимок всего дерева: тип, права, inode, время изменения, размер и SHA-256 файлов.

    Ссылки не разыменовываются. Размер каталога зависит от файловой системы
    и не записывается; изменение состава каталога видно по его времени изменения.
    """
    state = {".": _entry(root)}
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            state[str(path.relative_to(root))] = _entry(path)
    return state


def _entry(path: Path) -> TreeEntry:
    info = path.lstat()
    regular = stat.S_ISREG(info.st_mode)
    return TreeEntry(
        stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), info.st_ino, info.st_mtime_ns,
        info.st_size if regular else None, sha256(path.read_bytes()) if regular else None,
    )


def tree_changes(before: dict[str, TreeEntry], after: dict[str, TreeEntry]) -> tuple[dict, set, dict]:
    added = {name: after[name] for name in after.keys() - before.keys()}
    removed = before.keys() - after.keys()
    changed = {name: (before[name], after[name]) for name in before.keys() & after.keys() if before[name] != after[name]}
    return added, removed, changed


def router_path(root: Path, path: str) -> Path:
    """Путь роутера внутри временного дерева."""
    return root / path.lstrip("/")


def build_tree(root: Path) -> None:
    """Разложить обезличенный снимок по путям роутера.

    Части Xray — байты фикстур; `xkeen.json` — та же сериализация проекции,
    что и у источников в памяти; списки — текст снимка; init — только четыре
    флага снимка строками `name="value"`, исходного init в снимке нет; `geoip.dat` —
    искусственные байты; ответы RCI — файл-заменитель транспорта.
    """
    xkeen = load_xkeen_snapshot()
    files = {
        **{f"{XRAY_CONFIG_DIRECTORY}/{name}": content for name, content in load_xray_snapshot_files().items()},
        XKEEN_SETTINGS_PATH: (json.dumps(xkeen["settings"], indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        **{f"{XKEEN_LIST_DIRECTORY}/{name.value}": xkeen["lists"][name.value].encode("utf-8") for name in LIST_NAMES},
        XKEEN_INIT_PATH: "".join(f'{name}="{value}"\n' for name, value in xkeen["init_flags"].items()).encode("ascii"),
        f"{XRAY_ASSET_DIRECTORY}/{GEOIP_FILE_NAME}": bytes(SYNTHETIC_GEOIP_SIZE),
        f"/{TREE_KEENETIC}": json.dumps(load_keenetic_snapshot(), ensure_ascii=False).encode("utf-8"),
    }
    for path, content in files.items():
        target = router_path(root, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (root / METADATA_PARENT).mkdir()


class TreeSources:
    """Источники, которые при каждом вызове читают файлы дерева и разбирают их функциями адаптеров.

    Файлы только читаются; `calls` считает обращения по источникам. Процесса
    в дереве нет: его наблюдение даёт источник в памяти.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self.calls: Counter[str] = Counter()

    def _read(self, source: str, path: str) -> bytes:
        self.calls[source] += 1
        return router_path(self._root, path).read_bytes()

    def _rci(self, source: str, resource: str) -> object:
        return json.loads(self._read(source, f"/{TREE_KEENETIC}"))[resource]

    def current_policies(self):
        return policies_from_rci(self._rci("policies", POLICIES_RESOURCE))

    def current_hotspot_settings(self):
        return hotspot_settings_from_rci(self._rci("hotspot", HOTSPOT_SETTINGS_RESOURCE))

    def current_registrations(self):
        return registrations_from_rci(self._rci("registrations", REGISTRATIONS_RESOURCE))

    def current_hotspot_runtime(self):
        return hotspot_runtime_from_rci(self._rci("runtime", HOTSPOT_RUNTIME_RESOURCE))

    def current_xray_config(self):
        self.calls["xray"] += 1
        directory = router_path(self._root, XRAY_CONFIG_DIRECTORY)
        return xray_config_from_files({path.name: path.read_bytes() for path in directory.iterdir()})

    def current_xkeen_settings(self):
        return xkeen_settings_from_bytes(self._read("settings", XKEEN_SETTINGS_PATH))

    def current_xkeen_init(self):
        return xkeen_init_from_bytes(self._read("init", XKEEN_INIT_PATH))

    def current_xkeen_list(self, name: XKeenListName):
        return xkeen_list_from_bytes(name, self._read(name.value, f"{XKEEN_LIST_DIRECTORY}/{name.value}"))

    def current_geo_databases(self):
        return geo_inventory_from_files(
            {GEOIP_FILE_NAME: self._read("geodata", f"{XRAY_ASSET_DIRECTORY}/{GEOIP_FILE_NAME}")},
        )


def tree_reads(runs: int) -> Counter:
    """Обращения к файлам дерева за `runs` запусков, как у источников в памяти."""
    keenetic = dict.fromkeys(("policies", "hotspot", "registrations", "runtime", "geodata"), runs)
    proxy = dict.fromkeys(("xray", "settings", "init", *(name.value for name in LIST_NAMES)), 2 * runs)
    return Counter({**keenetic, **proxy})


class CountingStore:
    """Настоящее хранилище с подсчётом записей: повтор не должен вызывать write_metadata."""

    def __init__(self, store: ManagerMetadataFiles) -> None:
        self.store = store
        self.writes = 0

    def read_metadata(self):
        return self.store.read_metadata()

    def write_metadata(self, metadata, expected_revision):
        self.writes += 1
        return self.store.write_metadata(metadata, expected_revision)


class FirstConnectionFileTreeTests(FlowAssertions):
    """Копия снимка по путям роутера во временном каталоге и настоящий `ManagerMetadataFiles`."""

    def setUp(self):
        # Реальный путь: на macOS временный каталог находится за ссылкой /var.
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="keenvpn-zero-diff-")))
        self.addCleanup(shutil.rmtree, self.root, True)
        build_tree(self.root)
        self.protected = tuple(str(self.root) + path for path in PROTECTED_DIRECTORIES)
        self.sources = TreeSources(self.root)
        self.placement = InMemoryStoragePlacementSource(synthetic_storage_placement(str(self.root / "mnt" / "usb")))
        self.store = self.store_at(str(self.root / METADATA_DIRECTORY))
        self.flow = self.flow_for(self.store)
        self.file = self.root / METADATA_FILE

    def store_at(self, directory: str) -> CountingStore:
        return CountingStore(ManagerMetadataFiles(directory, protected_directories=self.protected))

    def flow_for(self, store) -> FirstConnection:
        sources = self.sources
        return FirstConnection(
            (sources, sources, sources, sources), (sources, sources, sources, sources), sources,
            InMemoryXrayProcessSource(synthetic_xray_process()), self.placement, store,
        )

    def expected_content(self, extra=None) -> bytes:
        return encode_manager_metadata(ManagerMetadata(self.placement.outcome, UnknownFields(extra or {})))

    def assert_only_metadata_changed(self, before, after, changed_entries):
        """Вне собственного каталога метаданных меняется только время изменения его родителя."""
        added, removed, changed = tree_changes(before, after)
        self.assertEqual(removed, set())
        self.assertLessEqual(set(changed), {METADATA_PARENT, *changed_entries})
        for name, (old, new) in changed.items():
            if name == METADATA_PARENT:
                self.assertEqual(old._replace(mtime_ns=new.mtime_ns), new)
        return added, changed

    def test_first_connection_adds_only_metadata_directory_and_file(self):
        before = tree_state(self.root)
        results = self.flow.run()
        self.assert_read_succeeded(results)
        self.assertEqual(results[2].data.outcome, "created")
        added, _ = self.assert_only_metadata_changed(before, tree_state(self.root), ())
        self.assertEqual(set(added), {METADATA_DIRECTORY, METADATA_FILE})
        self.assertEqual((added[METADATA_DIRECTORY].kind, added[METADATA_DIRECTORY].mode), (stat.S_IFDIR, 0o700))
        self.assertEqual(
            (added[METADATA_FILE].kind, added[METADATA_FILE].mode, added[METADATA_FILE].sha256),
            (stat.S_IFREG, 0o600, sha256(self.expected_content())),
        )
        self.assertEqual(self.store.writes, 1)
        self.assertEqual(self.sources.calls, tree_reads(1))

    def test_repeated_runs_leave_the_whole_tree_unchanged(self):
        first = self.flow.run()
        after_first = tree_state(self.root)
        revision = self.store.read_metadata().revision
        for _ in range(2):
            results = self.flow.run()
            self.assertEqual(views(results)[:2], views(first)[:2])
            self.assertEqual(results[2].data.outcome, "unchanged")
            self.assertEqual(results[2].data.metadata, first[2].data.metadata)
            # Байты, inode, время изменения и права файла и всех остальных объектов те же.
            self.assertEqual(tree_state(self.root), after_first)
        self.assertEqual(self.store.writes, 1)
        self.assertEqual(self.store.read_metadata().revision, revision)
        self.assertEqual(revision, metadata_revision(self.file.read_bytes()))
        self.assertEqual(self.sources.calls, tree_reads(3))

    def test_existing_file_keeps_unknown_fields_and_configs_stay_unchanged(self):
        self.store.store.write_metadata(ManagerMetadata(None, UnknownFields(FUTURE_FIELDS)), None)
        before = tree_state(self.root)
        results = self.flow.run()
        self.assert_read_succeeded(results)
        self.assertEqual(results[2].data.outcome, "created")
        after_first = tree_state(self.root)
        added, changed = self.assert_only_metadata_changed(before, after_first, (METADATA_DIRECTORY, METADATA_FILE))
        self.assertEqual(added, {})
        replaced = changed[METADATA_FILE][1]
        self.assertEqual(
            (replaced.kind, replaced.mode, replaced.sha256),
            (stat.S_IFREG, 0o600, sha256(self.expected_content(FUTURE_FIELDS))),
        )
        written = json.loads(self.file.read_bytes())
        self.assertEqual(list(written), ["format", "schema_version", "storage", *FUTURE_FIELDS])
        self.assertEqual({key: written[key] for key in FUTURE_FIELDS}, FUTURE_FIELDS)
        for _ in range(2):
            self.assertEqual(self.flow.run()[2].data.outcome, "unchanged")
            self.assertEqual(tree_state(self.root), after_first)
        # Предварительная запись шла напрямую в хранилище, мимо счётчика.
        self.assertEqual(self.store.writes, 1)

    def test_changed_detected_placement_is_refused_without_any_write(self):
        self.flow.run()
        after_first = tree_state(self.root)
        content = self.file.read_bytes()
        base = self.placement.outcome
        data, limits = base.roles.data, base.history_limits
        cases = {
            "variant": replace(base, variant=TrackedValue(KNOWN, StorageVariant.EXTENDED)),
            "storage_id": replace(base, roles=replace(
                base.roles, data=replace(data, storage_id=TrackedValue(KNOWN, OTHER_STORAGE_ID)),
            )),
            "path": replace(base, roles=replace(
                base.roles, data=replace(data, path=TrackedValue(KNOWN, data.path.value + "-moved")),
            )),
            "verified": replace(base, roles=replace(base.roles, data=replace(data, verified=False))),
            "history_size_increased": replace(base, history_limits=replace(
                limits, size_bytes=TrackedValue(KNOWN, SYNTHETIC_HISTORY_SIZE * 2),
            )),
            "history_retention_increased": replace(base, history_limits=replace(
                limits, retention_seconds=TrackedValue(KNOWN, SYNTHETIC_HISTORY_RETENTION + 24 * 3600),
            )),
        }
        for name, detected in cases.items():
            with self.subTest(name):
                self.placement.outcome = detected
                self.assert_mismatch(self.flow.run())
                self.assertEqual(self.store.writes, 1)
                self.assertEqual(tree_state(self.root), after_first)
                self.assertEqual(self.file.read_bytes(), content)
        self.placement.outcome = base
        self.assertEqual(self.flow.run()[2].data.outcome, "unchanged")
        self.assertEqual(self.store.writes, 1)

    def test_unknown_field_inside_stored_placement_is_refused_without_write(self):
        stored = replace(self.placement.outcome, extra=UnknownFields({"future-field": 1}))
        self.store.store.write_metadata(ManagerMetadata(stored), None)
        before = tree_state(self.root)
        self.assert_mismatch(self.flow.run())
        self.assertEqual(self.store.writes, 0)
        self.assertEqual(tree_state(self.root), before)
        self.assertEqual(decode_manager_metadata(self.file.read_bytes()).metadata.storage.extra.export(), {"future-field": 1})

    def test_metadata_store_inside_active_configs_is_refused_without_touching_the_tree(self):
        before = tree_state(self.root)
        for path in (*PROTECTED_DIRECTORIES, f"{XRAY_CONFIG_DIRECTORY}/keenvpn", f"{XKEEN_LIST_DIRECTORY}/keenvpn"):
            with self.subTest(path):
                store = self.store_at(str(self.root) + path)
                results = self.flow_for(store).run()
                self.assert_read_succeeded(results)
                error = results[2].error
                self.assertEqual(
                    (error.category, error.code, error.reason),
                    (ErrorCategory.SOURCE_FAILED, MetadataStoreFailure.UNSAFE.value,
                     MetadataStoreReason.PROTECTED_DIRECTORY.value),
                )
                self.assertEqual(store.writes, 0)
                self.assertEqual(tree_state(self.root), before)


if __name__ == "__main__":
    unittest.main()
