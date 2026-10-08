# Чтение существующей установки

Сценарий `InspectInstallation` читает четыре области существующей установки одним вызовом: [состояние Keenetic](keenetic-state.md), [конфигурацию Xray и XKeen](proxy-config.md), инвентарь файлов GeoIP и GeoSite со ссылками на их наборы из правил и наблюдение процесса Xray. Модели геобаз и процесса описаны в `keenvpn.domain.geodata` и `keenvpn.domain.xray_process`. Код работает в памяти: он не обращается к роутеру, не запускает и не останавливает службы, не вызывает команды XKeen и init, не создаёт, не загружает и не обновляет базы и ничего не записывает. Успех описывает снимок на момент чтения, а не работу VPN, перехват трафика, готовность канала или маршрут клиента.

## Файлы геобаз

`GeoDatabaseFile(name, present, size, sha256, source, version)` описывает один файл каталога геобаз. Имя — имя файла без каталога по тем же правилам, что у [документа конфигурации](proxy-config.md#документ-конфигурации). Для найденного файла (`present=True`) обязательны размер и SHA-256 исходных байтов; хеш приводится к нижнему регистру. Для отсутствующего файла размер и хеш всегда `None`: такая запись отражает отсутствие базы в отчёте, база при этом не создаётся. `source` и `version` — известные источник и версия либо `None`: версия не выводится из имени файла, источник и способ обновления не угадываются. Любой печатный непустой текст допустим; размер любой длины не вызывает исключений.

Стандартные имена заданы константами `GEOIP_FILE_NAME` (`geoip.dat`), `GEOSITE_FILE_NAME` (`geosite.dat`) и словарём `STANDARD_FILE_NAMES` по типу `GeoDatabaseKind`. `standard_kind` возвращает тип стандартной базы по имени либо `None` для прочих файлов. `database(kind)` строит [`GeoDatabase`](routing-model.md) для условий маршрутизации: ссылка — имя файла, источник, версия и хеш — из записи; для отсутствующего файла возвращается `None`, а тип, противоречащий стандартному имени, отклоняется.

`to_diagnostic()` записи выводит источник и версию только в безопасной форме, а исходные значения остаются доверенному коду в полях и `database()`. `safe_geo_version(value)` пропускает короткий идентификатор релиза из букв, цифр, `.`, `_`, `+` и `-` до 128 символов. `safe_geo_source(value)` пропускает идентификатор из одного сегмента, например `v2fly`: буквы, цифры, `_`, `+`, `-` и точки только между непустыми частями, до 128 символов. `/` не допускается, поэтому абсолютные и относительные пути и форма вида `v2fly/geoip` скрываются. URL `http` или `https` сводится к схеме и хосту с портом. `userinfo`, путь, query и fragment URL могут содержать пароли и токены и не выводятся. Любое другое значение заменяется на `None`, а признаки `source_known` и `version_known` показывают, были ли сведения переданы.

`GeoDatabaseInventory(files)` хранит записи в порядке источника. Имена уникальны, записи для обоих стандартных имён присутствуют всегда — найденными или отсутствующими; прочие файлы каталога допустимы. `file(name)` возвращает запись по точному имени либо `None`, `standard(kind)` — запись стандартной базы. `to_diagnostic()` содержит записи и счётчики `present_count`, `missing_count` и `extra_count` (нестандартные файлы). `validate_geo_inventory(inventory)` проверяет инвентарь заново вместе с каждой записью: повреждённое поле записи отклоняется её кодом, расхождение после восстановления, повтор имени и неполный состав — кодом инвентаря.

`keenvpn.adapters.geodata_files` строит записи из уже полученных наблюдений: `geo_database_file_from_bytes(name, content, source=None, version=None)` вычисляет размер и SHA-256 по байтам, `geo_database_file_from_digest(name, size, sha256, ...)` принимает значения, вычисленные транспортом (`stat`, `sha256sum`), `missing_geo_database_file(name, ...)` описывает отсутствующий файл, `geo_inventory_from_files(files)` собирает инвентарь из словаря «имя → байты либо `None`» и добавляет не упомянутые стандартные имена как отсутствующие. Каталог геобаз установленного Xray на проверенной платформе задан `XRAY_ASSET_DIRECTORY`; перечисление каталога, чтение по SSH и ограничение размера файла в репозитории не реализованы.

## Ссылки на наборы из конфигурации Xray

`XrayConfigSet.rule_list_values()` и `rule_list_values(parts)` из `keenvpn.domain.xray_config` возвращают значения списков доменов и адресов в порядке частей и полей файла: `domain`, `domains`, `ip`, `source`, `sourceIP` и `localIP` правил маршрутизации, `domains`, `expectIPs`, `expectedIPs` и `unexpectedIPs` серверов DNS и ключи `dns.hosts`. Поля `StringList` принимают массив строк либо строку с разделением по запятым, как декодер Xray; `domains` сервера DNS — только массив. Алиасы выбираются так же, как в Xray: `source` правила учитывается, только если `sourceIP` отсутствует или равно `null`, причём пустой массив `sourceIP` уже отключает `source`. `expectIPs` сервера DNS учитывается, только если `expectedIPs` отсутствует, равно `null` или пустому массиву. Недействующий алиас не даёт ссылок, а `null` в выбирающем поле не считается неподдержанной структурой. `domain` и `domains` правила действуют оба. Каждое значение `RuleListValue` хранит часть, путь с исходным индексом элемента, семейство `ConditionFamily` и признак `qualified`: ключи `dns.hosts` не принимают префиксы `ext-domain:` и `ext-ip:`, а в их пути стоит порядковый номер ключа, а не сам ключ. Значения — домены, адреса и ссылки: это данные для доверенного кода, в сводку и представления они не входят.

`parse_geo_reference(value)` разбирает значение по правилам загрузчика Xray и возвращает `GeoReference`, `UnsupportedGeoReference` либо `None` для значения без префикса геобазы:

| Семейство | Префикс | Файл | Разбор |
|---|---|---|---|
| Домены | `geosite:` | `geosite.dat` | Код набора до первого `@`, атрибуты после него |
| Домены | `ext:`, `ext-domain:` | Имя файла из ссылки | `файл:набор@атрибуты`; ровно одно двоеточие между файлом и набором |
| Адреса | `geoip:` | `geoip.dat` | Ведущий `!` — отрицание набора |
| Адреса | `ext:`, `ext-ip:` | Имя файла из ссылки | `файл:!набор`; ровно одно двоеточие между файлом и набором |

Префиксы сравниваются с учётом регистра, как в Xray, поэтому `GEOSITE:` — обычный домен. Пустые имя файла и код набора, лишние двоеточия и непечатные символы, которые Xray не загрузит, дают `UnsupportedGeoReference` с частью, путём и семейством без текста. `GeoReference` хранит часть, путь, семейство, признак внешнего файла, имя файла, код набора как написан, отрицание и атрибуты; `code` возвращает код в верхнем регистре, как его ищет Xray, `file_name_safe` — можно ли показывать имя внешнего файла (имя без каталога), `standard_kind` — тип стандартной базы. Ссылка без внешнего файла всегда относится к стандартному файлу своего семейства. `geo_references(config)` собирает ссылки набора частей.

## Состояние геобаз

`GeoDataState(inventory, references)` объединяет инвентарь и ссылки; `assemble_geodata_state(inventory, config)` собирает его из инвентаря и набора частей Xray. `resolve()` сопоставляет каждую разобранную ссылку с записью файла только по имени и за один проход:

| `GeoFileStatus` | Значение |
|---|---|
| `present` | Файл есть в инвентаре и найден |
| `missing` | Файл описан инвентарём как отсутствующий |
| `unknown` | Файла нет в инвентаре: источник его не наблюдал |

Сопоставление не подтверждает, что Xray загрузил файл и что набор существует внутри него. `to_diagnostic()` содержит записи файлов со счётчиками `reference_count` и `set_count` (различные коды наборов без учёта регистра), ссылки с частью, путём, семейством, признаком внешнего файла, именем файла (`None`, если имя непригодно для показа), статусом файла, отрицанием и числом атрибутов, список неподдержанных ссылок и счётчики `present_count`, `missing_count`, `extra_count`, `reference_count`, `resolved_count` и `unresolved_count`. Коды наборов, домены и адреса в диагностику не входят. `validate_geodata_state(state)` заново проверяет инвентарь и каждую ссылку.

| Код `GeoDataErrorCode` | Причина |
|---|---|
| `invalid_geo_database_file` | Недопустимое имя, признак наличия, размер, хеш, источник или версия записи; тип базы противоречит стандартному имени |
| `invalid_geo_inventory` | Записи не кортеж `GeoDatabaseFile`, имя повторяется, нет записи стандартного имени, запись изменена после создания |
| `invalid_geo_reference` | Поля ссылки недопустимы или противоречат друг другу; значение для разбора не `RuleListValue`; набор частей не `XrayConfigSet` |
| `invalid_geodata_state` | Ссылки не кортеж `GeoReference` и `UnsupportedGeoReference` либо состояние другого типа |

## Процесс Xray

`XrayProcessObservation(pids, ready_marker)` хранит PID процессов Xray в порядке наблюдения и наличие ready-маркера XKeen. PID — целые от 1 до `PID_MAX` без повторов; несколько PID сохраняются все, поскольку вспомогательные вызовы `xray api` видны под тем же именем процесса и «основной» по ним не выбирается. `state` возвращает согласованность процесса и маркера:

| `XrayProcessState` | Условие | `consistent` |
|---|---|---|
| `stopped` | Процесса нет и маркер снят | да |
| `running` | Один процесс и маркер готовности | да |
| `process_without_marker` | Процесс есть, маркера нет | нет |
| `marker_without_process` | Маркер остался без процесса | нет |
| `multiple_processes` | Несколько процессов; состояние службы по ним не выводится | нет |

Расхождение процесса и маркера — отдельное состояние, а не работающий VPN. Состояние `running` тоже не подтверждает готовность канала, правила перехвата, DNS или маршрут клиента: это только наблюдение службы. `to_diagnostic()` содержит `process_count`, `pids`, `ready_marker`, `state` и `consistent`; `validate_xray_process_observation(observation)` проверяет модель заново. Отказ — `XrayProcessError` с кодом `invalid_xray_process_observation`.

`keenvpn.adapters.xkeen_runtime.xray_process_from_pidof(output, ready_marker)` разбирает уже полученный вывод `pidof`: PID через пробелы, пустой вывод — отсутствие процесса. Токен не из цифр, ноль, ведущий ноль, число длиннее `PID_MAX`, повтор и не ASCII отклоняются; длина проверяется до преобразования в число. Имя процесса и пути заданы `XRAY_PROCESS_NAME`, `XKEEN_RUNTIME_DIRECTORY` и `XKEEN_READY_MARKER_PATH`. Запуск `pidof`, проверка файла и коды возврата принадлежат транспорту; команды XKeen и init не вызываются — даже `xkeen -status` меняет служебные файлы.

## Прикладной сценарий

`InspectInstallation()` не имеет параметров, кроме версии контракта. `InspectInstallationHandler(keenetic, proxy, geodata, processes)` получает обработчики `InspectKeeneticStateHandler` и `InspectProxyConfigHandler` и два порта `application.ports`:

| Источник | Метод | Модель |
|---|---|---|
| `InspectKeeneticStateHandler.read()` | четыре источника [состояния Keenetic](keenetic-state.md#прикладной-сценарий) | `KeeneticNativeState` |
| `InspectProxyConfigHandler.read()` | шесть источников [конфигурации Xray и XKeen](proxy-config.md#прикладной-сценарий) | `ProxyConfigModels` |
| `GeoDatabaseSource` | `current_geo_databases()` | `GeoDatabaseInventory` |
| `XrayProcessSource` | `current_xray_process()` | `XrayProcessObservation` |

Метод `read()` обработчика возвращает модели для доверенного кода либо `ErrorDetail` с теми же кодами, что и его `execute()`; общий сценарий использует его, а не повторяет чтение. Порядок фиксирован: состояние Keenetic, конфигурация Xray и XKeen, инвентарь геобаз, наблюдение процесса. Каждый источник вызывается один раз; после отказа или некорректного ответа следующие источники не читаются, частичного результата нет. Ссылки на наборы разбираются из прочитанных частей Xray и сопоставляются с инвентарём.

```python
from keenvpn.application.installation import InspectInstallation, InspectInstallationHandler
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.geodata import GeoDatabaseFile, GeoDatabaseInventory
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


class FixedSources:
    """Искусственные данные; реальные ресурсы и файлы читают адаптеры роутера."""

    def current_policies(self):
        return KeeneticPolicySet((KeeneticPolicy("Policy2", "xkeen"),))

    def current_hotspot_settings(self):
        return KeeneticHotspotSettings({"host": [{"mac": "02:00:00:00:00:01", "policy": "Policy2"}]})

    def current_registrations(self):
        return KeeneticRegistrations({"fixture-phone": {"mac": "02:00:00:00:00:01"}})

    def current_hotspot_runtime(self):
        return KeeneticHotspotRuntime({"host": [{"mac": "02:00:00:00:00:01", "active": True}]})

    def current_xray_config(self):
        return XrayConfigSet((ConfigDocument("05_routing.json", b'{"routing": {"rules": ['
                                             b'{"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"}, '
                                             b'{"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "blocked"}]}}'),))

    def current_xkeen_settings(self):
        return XKeenSettings(ConfigDocument("xkeen.json", b'{"xkeen": {"killswitch": "on"}}'))

    def current_xkeen_init(self):
        return parse_xkeen_init(b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\nipv6_support="on"\n')

    def current_xkeen_list(self, name):
        return XKeenList(name, b"53\n" if name is XKeenListName.PORT_EXCLUDE else b"")

    def current_geo_databases(self):
        return GeoDatabaseInventory((
            GeoDatabaseFile("geoip.dat", True, 1024, "3f" * 32, "fixture-source", "fixture-release"),
            GeoDatabaseFile("geosite.dat", False),
        ))

    def current_xray_process(self):
        return XrayProcessObservation((4242,), True)


sources = FixedSources()
handler = InspectInstallationHandler(
    InspectKeeneticStateHandler(sources, sources, sources, sources),
    InspectProxyConfigHandler(sources, sources, sources, sources),
    sources, sources,
)
result = handler.execute(InspectInstallation())
assert result.succeeded
assert result.data.keenetic.policy_ids == ("Policy2",)
assert result.data.proxy.xkeen.port_53.port_exclude_entry is True
assert [item.file_status for item in result.data.geodata.references] == ["present", "missing"]
assert result.data.geodata.files[0].version == "fixture-release"
assert result.data.xray_process.state == "running"
assert "geoip:ru" not in str(result.data.to_dict())
```

При успехе `data` — `InstallationView` с четырьмя частями:

| Поле | Содержимое |
|---|---|
| `keenetic` | `KeeneticStateView` — те же поля, что у [чтения состояния Keenetic](keenetic-state.md#прикладной-сценарий) |
| `proxy` | `ProxyConfigView` — те же поля, что у [чтения конфигурации Xray и XKeen](proxy-config.md#прикладной-сценарий) |
| `geodata` | `GeoDataView`: `files` — кортеж `GeoDatabaseFileView` (имя, наличие, размер, SHA-256, `source_known`, безопасный источник, `version_known`, безопасная версия, `reference_count`, `set_count`); `references` — кортеж `GeoReferenceView` (часть, путь, семейство, `external`, имя файла или `None`, `file_status`, `negated`, `attribute_count`); `unsupported_references` — кортеж `UnsupportedGeoReferenceView`; счётчики `present_count`, `missing_count`, `extra_count`, `reference_count`, `resolved_count`, `unresolved_count` |
| `xray_process` | `XrayProcessView`: `process_count`, `pids`, `ready_marker`, `state`, `consistent` |

Имена файлов, PID, теги и технические идентификаторы роутера показываются; коды наборов геобаз, домены, адреса, пути, пароли, MAC и имена устройств в представление не входят, модели источников недостижимы из результата. Известные источник и версия базы показываются только в безопасной форме, описанной в разделе о файлах геобаз; вывод о способе обновления базы не делается. `to_dict()` возвращает JSON-совместимый словарь, представление одного результата не читает источники повторно.

| Ситуация | Категория и код |
|---|---|
| Неверный тип команды | `invalid_request` / `invalid_command` |
| Неверная версия команды | `invalid_request` / `unsupported_contract_version` |
| Отказ или некорректный ответ источника Keenetic | коды [чтения состояния Keenetic](keenetic-state.md#прикладной-сценарий) без изменения |
| Отказ или некорректный ответ источника Xray или XKeen | коды [чтения конфигурации Xray и XKeen](proxy-config.md#прикладной-сценарий) без изменения |
| Источник геобаз или процесса вызвал исключение | `source_failed` / `geo_databases_unavailable` или `xray_process_unavailable` |
| Источник вернул объект другого типа, включая подкласс | `invalid_source_data` / `invalid_geo_databases` или `invalid_xray_process`; `reason=None` |
| Модель повреждена после создания | тот же код источника; доменная причина в `reason` |
| Инвентарь и ссылки не удалось собрать | `invalid_source_data` / `installation_inconsistent`; доменная причина в `reason` |

Текст и цепочка исключений источников в результат не попадают, `KeyboardInterrupt` и `SystemExit` проходят наружу. Успех означает только согласованное чтение переданных источников: он не подтверждает принятие конфигурации Xray, загрузку геобаз, работу XKeen, kill-switch, перехват DNS или VPN и не меняет роутер.

## Ошибки домена

`GeoDataError` и `XrayProcessError` содержат машинный `code` и фиксированный текст без имён файлов, значений правил и вывода команд. Активное чужое исключение не сохраняется в `__context__` и `__cause__`.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_geodata.py -v
python3 -I -S -B -m unittest discover -s tests -p test_geodata_files.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xray_process.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xkeen_runtime.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_installation.py -v
```

Тесты используют [обезличенный снимок](../tests/fixtures/router_snapshot/README.md) для Keenetic, Xray и XKeen и искусственные значения для геобаз и процесса: в снимке нет файлов геобаз и состояния процессов, поэтому `tests/support/snapshot.py` даёт инвентарь с найденным `geoip.dat` неизвестной версии и отсутствующим `geosite.dat` и наблюдение с одним процессом и маркером. Проверяются разбор ссылок по правилам Xray, сопоставление с найденными, отсутствующими и неизвестными файлами, расхождение процесса и маркера, отказ каждого из двенадцати источников, повреждённые модели, отсутствие секретов в результатах и отсутствие терминала, файлов, сети и процессов во время сценария. Роутер и сеть не требуются.
