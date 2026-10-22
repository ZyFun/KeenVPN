# Чтение состояния Keenetic

`keenvpn.domain.keenetic_native` описывает прочитанное состояние Keenetic: действующие [политики](keenetic-policies.md), назначения сегментов, [записи устройств](keenetic-devices.md), реестр регистраций и наблюдаемое состояние клиентов. Сценарий `InspectKeeneticState` читает четыре ресурса через раздельные источники и собирает их в один согласованный результат. Код работает в памяти: он не обращается к роутеру, не записывает настройки и не подтверждает фактический маршрут клиента.

## Раздельные источники

| Порт `application.ports` | Метод | Ресурс RCI | Модель |
|---|---|---|---|
| `KeeneticPolicySource` | `current_policies()` | `ip/policy` | `KeeneticPolicySet` |
| `KeeneticHotspotSettingsSource` | `current_hotspot_settings()` | `ip/hotspot` | `KeeneticHotspotSettings` |
| `KeeneticRegistrationSource` | `current_registrations()` | `known/host` | `KeeneticRegistrations` |
| `KeeneticHotspotRuntimeSource` | `current_hotspot_runtime()` | `show/ip/hotspot` | `KeeneticHotspotRuntime` |

Настройки, регистрация и runtime читаются отдельно и не смешиваются: сохранённое назначение берётся только из `ip/hotspot`, а вычисленная роутером политика из наблюдения его не заменяет. Источник возвращает готовую модель либо вызывает исключение при сбое и не должен менять настройки при чтении.

`keenvpn.adapters.keenetic_rci` преобразует разобранный JSON отдельного ресурса в модель: `policies_from_rci`, `hotspot_settings_from_rci`, `registrations_from_rci` и `hotspot_runtime_from_rci`. Имена ресурсов заданы константами `POLICIES_RESOURCE`, `HOTSPOT_SETTINGS_RESOURCE`, `REGISTRATIONS_RESOURCE` и `HOTSPOT_RUNTIME_RESOURCE`. Транспорт, таймауты, ограничение размера ответа и разбор вложенных статусов ошибок RCI в репозитории не реализованы; тесты получают модели из [обезличенного снимка](../tests/fixtures/router_snapshot/README.md).

## Модели источников

Каждая модель хранит независимый неизменяемый JSON-снимок прочитанного объекта по тем же правилам, что и [запись устройства](keenetic-devices.md#данные-и-сохранность): поддерживаются обычные `dict` со строковыми ключами, `list`, `str`, `bool`, `int`, конечные `float` и `None`; неизвестные поля, типы, порядок и отсутствие полей сохраняются. `export()` возвращает новую глубокую копию для доверенного кода и не является безопасным выводом. `repr()` моделей показывает только число записей.

### Назначение сегмента

`KeeneticSegmentAssignment(settings)` принимает одну запись массива `ip/hotspot.policy`. Поле `interface` обязательно: это технический идентификатор интерфейса сегмента в том же формате, что ID в [режимах сегмента](keenetic-segments.md).

| `mode` (`SegmentPolicyMode`) | Сохранённые поля |
|---|---|
| `explicit` | Непустой допустимый `policy` |
| `unassigned` | `policy` отсутствует либо пуст |
| `unknown` | `policy` другого типа или недопустимого формата |

`access_denied` отмечает `access: deny` или `deny: true` и хранится отдельно от политики: запрет сегмента не превращается в политику и не снимается чтением. `read_only` истинен для `unknown` и для неподдержанного или противоречивого режима доступа по тем же правилам, что у записи устройства. `unassigned` не означает прямой доступ: политика такого сегмента определяется роутером и здесь не вычисляется.

Запись описывает только назначение сегмента. Какие устройства относятся к сегменту, модель не знает: состав не выводится из наблюдаемого интерфейса записей, имени или адреса. Для расчёта режимов состав по-прежнему передаётся явно в `KeeneticSegment`.

### Настройки hotspot

`KeeneticHotspotSettings(document)` принимает объект `ip/hotspot`. Массив `host` даёт настройки записей устройств (`host_settings`), массив `policy` — назначения сегментов (`segment_assignments`); отсутствующий массив равен пустому. Остальные поля, например `auto-register`, сохраняются в снимке без разбора. Каждая запись `host` проверяется как `KeeneticDevice`, поэтому запись без допустимого MAC даёт `invalid_device_mac`. Не-список или элемент другого типа отклоняется кодом `invalid_hotspot_settings`.

### Реестр регистраций

`KeeneticRegistrations(document)` принимает объект `known/host`: ключ — имя регистрации, значение — объект с `mac`. Имена — персональные данные, они доступны только через `export()`. `identities` возвращает ключи MAC сопоставимых записей в порядке источника с повторами, `for_identity(identity)` — копии всех регистраций одного MAC по именам без учёта регистра MAC. Запись без допустимого `mac` сохраняется, не сопоставляется и учитывается в `unresolvable_count`.

### Наблюдаемое состояние

`KeeneticHotspotRuntime(document)` принимает объект `show/ip/hotspot` с массивом `host`. `observations` возвращает копии записей, `for_identity(identity)` — все наблюдения одного MAC без выбора первого. Наблюдение относится к моменту чтения и не является настройкой: `active_count` считает только булев `true`, `registered_count` — булев `registered`.

## Сборка состояния

`assemble_keenetic_state(policies, hotspot, registrations, runtime)` сопоставляет источники только по MAC и возвращает `KeeneticNativeState`:

- для каждой записи `host` создаётся `KeeneticDevice`; регистрации того же MAC попадают в `details["registration"]` по именам, единственное наблюдение — в `details["observation"]`;
- наблюдение привязывается, только когда и запись `host`, и наблюдение этого MAC единственны. Несколько наблюдений одного MAC или несколько записей `host` с одним MAC не выбираются по первому: записи остаются без наблюдения с `presence = unknown`, а ключ MAC попадает в `ambiguous_observations`; регистрации при этом копируются во все записи этого MAC, поскольку ключуются по имени;
- регистрации и наблюдения без записи `host` перечисляются ключами в `registrations_without_device` и `runtime_without_device`; они не становятся устройствами и не отбрасываются;
- порядок и состав записей совпадают с `ip/hotspot.host`; записи не объединяются по имени, IP или наблюдаемому интерфейсу;
- ссылки записей и сегментов на отсутствующие политики не удаляются и не подменяются: они видны в счётчиках `missing_policy_count` и `segment_missing_policy_count`.

Состояние хранит все четыре источника, инвентарь записей `devices` и назначения сегментов `segments`. Конструктор заново выводит сопоставление из источников и отклоняет несогласованные поля кодом `invalid_native_state`; `validate_keenetic_state(state)` повторяет эту проверку для готового объекта. Результат — снимок на момент чтения: он не проверяет согласованность с текущим роутером и не является черновиком применения.

## Прикладной сценарий

`InspectKeeneticState()` не имеет параметров, кроме версии контракта. `InspectKeeneticStateHandler(policies, hotspot, registrations, runtime)` получает четыре источника и вызывает каждый ровно один раз в фиксированном порядке: политики, настройки hotspot, регистрация, runtime. После отказа или некорректного ответа следующие источники не читаются; частичного результата нет. Метод `read()` обработчика выполняет то же чтение и возвращает `KeeneticNativeState` для доверенного кода либо `ErrorDetail` с теми же кодами; его использует [чтение существующей установки](installation.md).

```python
from keenvpn.application.keenetic_state import InspectKeeneticState, InspectKeeneticStateHandler
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet


class FixedSources:
    """Искусственные данные; реальные ресурсы читает адаптер роутера."""

    def current_policies(self):
        return KeeneticPolicySet((KeeneticPolicy("Policy0", "NoVPN"), KeeneticPolicy("Policy2", "xkeen")))

    def current_hotspot_settings(self):
        return KeeneticHotspotSettings({
            "policy": [{"interface": "Bridge0", "policy": "Policy0"}, {"interface": "Bridge1", "access": "deny"}],
            "host": [
                {"mac": "02:00:00:00:00:01", "access": "permit", "permit": True, "policy": "Policy2"},
                {"mac": "02:00:00:00:00:02", "access": "deny", "deny": True},
            ],
        })

    def current_registrations(self):
        return KeeneticRegistrations({"fixture-phone": {"mac": "02:00:00:00:00:01"}})

    def current_hotspot_runtime(self):
        return KeeneticHotspotRuntime({"host": [{"mac": "02:00:00:00:00:01", "active": True, "registered": True}]})


sources = FixedSources()
result = InspectKeeneticStateHandler(sources, sources, sources, sources).execute(InspectKeeneticState())
assert result.succeeded
assert result.data.policy_ids == ("Policy0", "Policy2")
assert [segment.access_denied for segment in result.data.segments] == [False, True]
assert result.data.devices.explicit_count == 1
assert result.data.devices.access_denied_count == 1
assert result.data.devices.with_observation_count == 1
assert result.data.registrations.without_device_count == 0
```

При успехе `data` — `KeeneticStateView`:

| Поле | Содержимое |
|---|---|
| `policy_count`, `policy_ids` | Число и технические ID политик в порядке источника |
| `segments` | `KeeneticSegmentView` для каждого назначения: `segment_id`, `assignment`, `policy_id`, `access_denied`, `read_only` |
| `segment_missing_policy_count` | Назначения сегментов с ID, которого нет в списке политик |
| `devices` | `KeeneticDeviceCountsView`: счётчики инвентаря `record_count`, `distinct_mac_count`, `online_count`, `offline_count`, `unknown_count`, `observation_mismatch_count`; режимы назначения `explicit_count`, `inherit_count`, `unassigned_count`, `unknown_assignment_count`; `access_denied_count`, `read_only_count`, `with_registration_count`, `with_observation_count`, `ambiguous_observation_count`, `missing_policy_count` |
| `registrations` | `KeeneticRegistrationCountsView`: `registration_count`, `distinct_mac_count`, `duplicate_mac_count`, `unresolvable_count`, `without_device_count` |
| `runtime` | `KeeneticRuntimeCountsView`: `record_count`, `distinct_mac_count`, `duplicate_mac_count`, `unresolvable_count`, `active_count`, `registered_count`, `without_device_count` |

ID политик и интерфейсов сегментов — технические идентификаторы роутера, как `candidates` в [определении политики](application.md#определение-политики-keenetic). MAC, имена, адреса, описания политик и неизвестные поля в представление не входят; модели источников и собранное состояние недостижимы из результата. `to_dict()` возвращает JSON-совместимый словарь, представление одного результата не читает источники повторно.

| Ситуация | Категория и код |
|---|---|
| Неверный тип команды | `invalid_request` / `invalid_command` |
| Неверная версия команды | `invalid_request` / `unsupported_contract_version` |
| Источник вызвал исключение | `source_failed` / `keenetic_policies_unavailable`, `keenetic_hotspot_unavailable`, `keenetic_registrations_unavailable` или `keenetic_runtime_unavailable` |
| Источник вернул объект другого типа, включая подкласс | `invalid_source_data` / `invalid_keenetic_policies`, `invalid_keenetic_hotspot`, `invalid_keenetic_registrations` или `invalid_keenetic_runtime`; `reason=None` |
| Модель повреждена после создания | тот же код источника; доменная причина в `reason` |
| Источники не удалось согласовать при сборке | `invalid_source_data` / `keenetic_state_inconsistent`; доменная причина в `reason` |

Текст и цепочка исключений источников в результат не попадают, `KeyboardInterrupt` и `SystemExit` проходят наружу. Успех означает только согласованное чтение переданных источников: он не подтверждает разрешённые подключения политик, фактическое наследование, работу XKeen или VPN и не меняет роутер.

## Список устройств для меню

`ListKeeneticDevices()` из `keenvpn.application.keenetic_devices` показывает записи `ip/hotspot.host` списком для пункта меню «Список, поиск, текущие назначения». `ListKeeneticDevicesHandler(keenetic)` принимает `InspectKeeneticStateHandler` и читает источники его методом `read()`: порядок чтения, коды отказов и правило «без частичного результата» те же, что у `InspectKeeneticState`. Список строится из собранного состояния в памяти; домен и представление `KeeneticStateView` не меняются.

```python
from keenvpn.application.keenetic_devices import ListKeeneticDevices, ListKeeneticDevicesHandler
from keenvpn.application.keenetic_state import InspectKeeneticStateHandler
from keenvpn.domain.keenetic_native import KeeneticHotspotRuntime, KeeneticHotspotSettings, KeeneticRegistrations
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet


class FixedSources:
    """Искусственные данные; реальные ресурсы читает адаптер роутера."""

    def current_policies(self):
        return KeeneticPolicySet((KeeneticPolicy("Policy0", "NoVPN"), KeeneticPolicy("Policy2", "xkeen")))

    def current_hotspot_settings(self):
        return KeeneticHotspotSettings({
            "policy": [{"interface": "Bridge0", "policy": "Policy0"}, {"interface": "Bridge1", "access": "deny"}],
            "host": [
                {"mac": "02:00:00:00:00:01", "access": "permit", "permit": True, "policy": "Policy2"},
                {"mac": "02:00:00:00:00:02", "access": "deny", "deny": True},
            ],
        })

    def current_registrations(self):
        return KeeneticRegistrations({"fixture-phone": {"mac": "02:00:00:00:00:01"}})

    def current_hotspot_runtime(self):
        return KeeneticHotspotRuntime({"host": [
            {"mac": "02:00:00:00:00:01", "active": True, "hostname": "phone-host", "interface": {"id": "Bridge0"}},
        ]})


sources = FixedSources()
keenetic = InspectKeeneticStateHandler(sources, sources, sources, sources)
result = ListKeeneticDevicesHandler(keenetic).execute(ListKeeneticDevices())
assert result.succeeded
first, second = result.data.devices
assert (first.name, first.assignment, first.policy_id, first.policy_present) == ("fixture-phone", "explicit", "Policy2", True)
assert (first.presence, first.observed_interface_id, first.segment_match) == ("online", "Bridge0", "matched")
assert first.segment.policy_id == "Policy0"
assert (second.name_known, second.registration_count, second.access_denied) == (False, 0, True)
assert (second.presence, second.presence_reason, second.segment_match) == ("unknown", "no_observation", "not_observed")
assert "phone-host" not in str(result.data.to_dict())
```

При успехе `data` — `DeviceListView`:

| Поле | Содержимое |
|---|---|
| `policy_count`, `policy_ids` | Число и технические ID политик в порядке источника |
| `segments`, `segment_missing_policy_count` | `KeeneticSegmentView` для каждого назначения `ip/hotspot.policy` и число назначений с ID, которого нет в списке политик |
| `counts` | `DeviceCountsView`: `record_count`, `distinct_mac_count`, `duplicate_mac_count` (записи, чей MAC повторяется), `online_count`, `offline_count`, `unknown_count`, `explicit_count`, `inherit_count`, `unassigned_count`, `unknown_assignment_count`, `missing_policy_count`, `access_denied_count`, `read_only_count`, `hidden_name_count`, `ambiguous_observation_count`, `registrations_without_device_count`, `runtime_without_device_count` |
| `devices` | `DeviceEntryView` для каждой записи `ip/hotspot.host` в порядке источника |

Поля `DeviceEntryView`:

| Поле | Содержимое |
|---|---|
| `position` | Индекс записи в `ip/hotspot.host`, счёт с нуля; различает записи с одинаковыми или скрытыми именами |
| `registration_count`, `registration_names` | Имена регистраций `known/host` того же MAC в порядке реестра; имя вне формата (пустое, с пробелами по краям, непечатное или длиннее 64 символов) — `None` |
| `name_known`, `name` | `name` задано только при единственной регистрации; при нескольких имена перечислены в `registration_names`, первое не выбирается |
| `assignment`, `policy_id`, `policy_present` | Режим сохранённого назначения (`explicit`, `inherit`, `unassigned`, `unknown`), ID политики только для `explicit` и признак её наличия в `policy_ids`; для других режимов `None` |
| `presence`, `presence_reason` | `online`, `offline` или `unknown` по наблюдению; причина только для `unknown`: `no_observation`, `ambiguous_observation` (MAC повторяется среди записей или наблюдений) или `active_unknown` (признак активности не булев) |
| `access_denied`, `read_only`, `mac_duplicate` | Запрет доступа, «только просмотр» по правилам записи устройства и повтор MAC среди записей |
| `observed_interface_known`, `observed_interface_id` | Наблюдался ли интерфейс и его технический ID; ID показан, только когда наблюдаемое значение совпало с интерфейсом одного из назначений `segments` (`matched` или `ambiguous`), иначе `None`: наблюдение может содержать MAC, адрес или имя хоста вместо ID интерфейса |
| `segment_match`, `segment` | `not_observed`, `unassigned`, `matched` или `ambiguous`; `segment` — `KeeneticSegmentView` назначения с тем же интерфейсом только при `matched` |

Сопоставление сегмента выполняется по техническому ID наблюдаемого интерфейса и не выводит состав сегмента и действующую политику устройства: при нескольких назначениях с одним интерфейсом ни одно не выбирается. Наблюдаемое значение без назначения сегмента остаётся известным, но скрытым: представление показывает только ID, которые уже присутствуют в `ip/hotspot.policy`. `unknown` у online не означает offline. Каталоги подписей `ASSIGNMENT_LABELS`, `PRESENCE_LABELS`, `PRESENCE_REASON_LABELS` и `SEGMENT_MATCH_LABELS` только для чтения; меню показывает их, а не вычисляет состояния. `to_dict()` возвращает JSON-совместимый словарь с ключами `policy_count`, `policy_ids`, `segments`, `segment_missing_policy_count`, `counts` и `devices`; имя регистрации встречается только в полях `name` и `registration_names`. Модели источников и собранное состояние недостижимы из результата.

| Ситуация | Категория и код |
|---|---|
| Неверный тип команды или версия | `invalid_request` / `invalid_command`, `unsupported_contract_version` |
| Отказ, некорректный ответ или несогласованность источников | коды сценария `inspect_keenetic_state` из таблицы выше без изменения |
| Список не удалось собрать из прочитанного состояния | `invalid_source_data` / `device_list_inconsistent` |

## Ошибки домена

`KeeneticNativeError` содержит машинный `code` из `KeeneticNativeErrorCode` и фиксированный текст без исходных значений. Активное чужое исключение не сохраняется в `__context__` и `__cause__`.

| Код | Причина |
|---|---|
| `invalid_segment_assignment` | Запись назначения сегмента не объект JSON, без допустимого `interface` или с неподдерживаемыми данными |
| `invalid_hotspot_settings` | Объект `ip/hotspot` неподдерживаемого формата: `host` или `policy` не список объектов, либо модель повреждена |
| `invalid_registrations` | Объект `known/host` неподдерживаемого формата либо ключ сопоставления не `DeviceIdentity` |
| `invalid_hotspot_runtime` | Объект `show/ip/hotspot` неподдерживаемого формата либо ключ сопоставления не `DeviceIdentity` |
| `invalid_native_policies` | Передан не `KeeneticPolicySet` или список политик некорректен |
| `invalid_native_state` | Поля состояния несогласованы с источниками или имеют неверный тип |

Проверка записей `host` может возвращать [ошибки модели устройства](keenetic-devices.md#безопасный-вывод-и-ошибки), например `invalid_device_mac` или `invalid_device_data`.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_keenetic_native.py -v
python3 -I -S -B -m unittest discover -s tests -p test_keenetic_rci.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_keenetic_state.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_keenetic_devices.py -v
```

Тесты используют искусственные записи и [обезличенный снимок](../tests/fixtures/router_snapshot/README.md), из которого `tests/support/snapshot.py` собирает модели и управляемые источники. Проверяются сопоставление по MAC, записи без пары, неоднозначные наблюдения, отсутствующие политики, повреждённые модели, отказ каждого источника и отсутствие терминала, файлов, сети и процессов во время сценария. Список устройств проверяется на снимке и на искусственных источниках, где имена регистраций отличаются от имён хостов: порядок и поля записей, каждое состояние online, назначения и сопоставления сегмента, скрытые имена, повтор MAC, отсутствие имён хостов, адресов и MAC в результате. Роутер и сеть не требуются.
