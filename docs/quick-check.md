# Быстрая проверка без изменений

Сценарий `QuickCheck` из `keenvpn.application.quick_check` одним вызовом проверяет согласованность прочитанных источников между собой и явно перечисляет, что не проверялось. Его результат показывает пункт 1 → 7 «Быстрая проверка без изменений» [меню](cli-menu.md). [Сводка состояния](status-summary.md) отвечает, что настроено и наблюдается; быстрая проверка — согласованы ли источники и что из этого осталось непроверенным. Код работает в памяти: ничего не записывает, не запускает и не останавливает службы, не вызывает команды XKeen и init и не выполняет сетевых проб. Успех описывает снимок источников на момент чтения и не подтверждает работу VPN, перехват трафика или маршрут клиента; успешный прямой выход или резерв проверкой VPN не считается.

## Прикладной сценарий

`QuickCheck()` не имеет параметров, кроме версии контракта. `QuickCheckHandler(proxy, processes, geodata)` получает обработчик [чтения конфигурации Xray и XKeen](proxy-config.md#прикладной-сценарий) `InspectProxyConfigHandler`, порт `XrayProcessSource` и порт `GeoDatabaseSource`. `None` вместо любого из них означает, что источник не подключён: сценарий его не вызывает, а зависящие от него проверки получают `not_checked` с причиной `source_not_connected`.

Источники читаются по одному разу в фиксированном порядке теми же функциями, что у сводки: части Xray, `xkeen.json`, параметры init, список исключённых портов, список перехватываемых портов и наблюдение процесса — `read_summary_sources`, затем инвентарь геобаз — `read_geo_databases` с кодами [чтения установки](installation.md#прикладной-сценарий). Список исключённых адресов и состояние Keenetic не читаются: ни одна проверка от них не зависит. Проверки областей сводки берутся из `build_status_summary` по тем же ответам источников, второго чтения и второго вычисления нет. Отказ или некорректный ответ одного источника не прерывает чтение остальных и не делает сценарий неуспешным: зависящие от него проверки получают `not_checked` с кодом отказа в причине (например, `xkeen_init_unavailable` или `invalid_xray_config`), а описание отказа с [безопасным следующим шагом](application.md#безопасный-следующий-шаг) приводится один раз — в итоге чтения источника. Если у проверки несколько источников, указывается первый неподключённый или отказавший в порядке чтения. Сценарий отказывает только при неверной команде (`invalid_request` / `invalid_command`) или версии контракта (`invalid_request` / `unsupported_contract_version`), не читая источников.

```python
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.quick_check import QuickCheck, QuickCheckHandler
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.geodata import GEOIP_FILE_NAME, GEOSITE_FILE_NAME, GeoDatabaseFile, GeoDatabaseInventory
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


class FixedSources:
    """Искусственные данные; реальные файлы, процесс и каталог геобаз читают адаптеры роутера."""

    def current_xray_config(self):
        return XrayConfigSet((ConfigDocument("04_outbounds.json", b'{"outbounds": [{"tag": "proxy", "protocol": '
                                             b'"trojan"}, {"tag": "block", "protocol": "blackhole"}], "routing": '
                                             b'{"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": '
                                             b'"block"}], "balancers": [{"tag": "group", "selector": ["proxy"], '
                                             b'"fallbackTag": "block"}]}}'),))

    def current_xkeen_settings(self):
        return XKeenSettings(ConfigDocument("xkeen.json", b'{"xkeen": {"killswitch": "on"}}'))

    def current_xkeen_init(self):
        return parse_xkeen_init(b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\n')

    def current_xkeen_list(self, name):
        return XKeenList(name, b"53\n" if name is XKeenListName.PORT_EXCLUDE else b"")

    def current_xray_process(self):
        return XrayProcessObservation((4242,), True)

    def current_geo_databases(self):
        return GeoDatabaseInventory((
            GeoDatabaseFile(GEOIP_FILE_NAME, True, 1024, "3f" * 32), GeoDatabaseFile(GEOSITE_FILE_NAME, False),
        ))


sources = FixedSources()
proxy = InspectProxyConfigHandler(sources, sources, sources, sources)
result = QuickCheckHandler(proxy, sources, sources).execute(QuickCheck())
assert result.succeeded
assert result.data.outcome.value == "incomplete"
assert result.data.counts == {"passed": 6, "failed": 0, "not_checked": 2, "unsupported": 1}
assert [(item.code, item.status.value) for item in result.data.checks.items] == [
    ("xray_config_consistent", "passed"), ("geodata_references_resolved", "passed"),
    ("fallback_profile_consistent", "passed"), ("autostart_flag_unambiguous", "passed"),
    ("dns_port_53_mode_consistent", "passed"), ("xray_process_consistent", "passed"),
    ("interception_active", "unsupported"), ("dns_port_53_path", "not_checked"), ("vpn_reachable", "not_checked"),
]
assert all(item.state.value == "read" for item in result.data.sources)
assert "4242" not in str(result.to_dict())
unconnected = QuickCheckHandler(None, None, None).execute(QuickCheck()).data
assert unconnected.counts == {"passed": 0, "failed": 0, "not_checked": 8, "unsupported": 1}
assert all(item.state.value == "not_connected" for item in unconnected.sources)
```

## Проверки

Девять проверок в фиксированном порядке `CHECK_ORDER`; статус каждой — из [общего словаря](application.md#статусы-проверок). Шесть проверок областей сводки описаны в [сводке состояния](status-summary.md#области) и здесь не вычисляются заново; черновик в быструю проверку не входит — это состояние менеджера, а не установки, его показывает пункт 1 → 1. Три проверки согласованности добавлены построителями `keenvpn.application.checks`.

| Код | Источники | Статусы и причины |
| --- | --- | --- |
| `xray_config_consistent` | части Xray | `failed` / `duplicate_tags` — непустой тег повторяется там, где объединение частей его не схлопывает: внутри единственной части среди inbound, outbound или балансировщиков либо внутри первой части среди inbound и outbound (`Config.Override` заменяет только первую найденную запись, вторая остаётся, и Xray такой набор не загрузит; пустой тег и отсутствующее поле `tag` — одно и то же отсутствие имени, повтором не считаются); `unsupported` / `sections_repeated_across_parts` — раздел `routing` или `dns` есть в нескольких частях: Xray берёт раздел последней части целиком, а сводка действующий раздел не выбирает, поэтому ссылки и назначения правил оцениваются только при единственном разделе; `failed` / `unresolved_references` — `inboundTag` правила не среди inbound, `dns.tag` и непустых тегов отдельных серверов DNS, либо `outboundTag` или `balancerTag` правила или `fallbackTag` балансировщика не находит цель; `failed` / `rule_target_ambiguous` — правило указывает оба назначения или ни одного, в том числе когда назначение не прочитано строкой; `unsupported` / `tags_repeated_across_parts` — любой другой повтор непустого тега: внутри последующей части, между частями или у балансировщиков при нескольких частях; при объединении частей Xray заменяет inbound и outbound с тем же тегом и переписывает `routing` целиком, поэтому итог такого повтора зависит от объединения, которое сводка не моделирует; `unsupported` / `unsupported_structures` — сводка не прочитала часть мест конфигурации; иначе `passed`. Условия проверяются в этом порядке. Повторы тегов ищет доменная функция `tag_repeats` по исходным значениям раздельно внутри частей и между ними. «Успешно» подтверждает разрешимость ссылок по сводке, а не загрузку конфигурации Xray |
| `geodata_references_resolved` | части Xray и инвентарь геобаз | как у [проверки сводки установки](installation.md#проверки-сводки): `not_checked` / `no_references`, `failed` / `missing_files`, `failed` / `unsupported_references`, `unsupported` / `files_not_inventoried`, иначе `passed`; если инвентарь и конфигурацию не удалось согласовать (`GeoDataError`), — `not_checked` с кодом ошибки домена в причине |
| `fallback_profile_consistent` | части Xray и `xkeen.json` | из сводки, по [правилу режима резерва](status-summary.md#режим-резерва) |
| `autostart_flag_unambiguous` | параметры init | из сводки |
| `dns_port_53_mode_consistent` | параметры init, списки исключённых и перехватываемых портов | по [правилу порта 53](#порт-53) |
| `xray_process_consistent` | наблюдение процесса | из сводки; «успешно» подтверждает только согласованность процесса и маркера |
| `interception_active` | нет | из сводки, всегда `unsupported` / `interception_not_observed` |
| `dns_port_53_path` | нет, сетевая | всегда `not_checked` / `network_check_not_performed`: в сводке эта проверка привязана к области DNS и наследует отказ её источников, здесь это сетевая проверка, которая не выполняется в любом случае |
| `vpn_reachable` | нет, сетевая | всегда `not_checked` / `network_check_not_performed` |

Признак `active_network_check` всегда `False`: сетевые проверки не могут быть `passed` или `failed`, это проверяет набор проверок результата. Проверка, зависящая от неподключённого или отказавшего источника, никогда не бывает `passed`.

## Порт 53

Проверка `dns_port_53_mode_consistent` сравнивает выбранный режим с обоими списками портов и флагами init. Исключение считается выбранным, если порт 53 записан в `port_exclude.lst` отдельной записью или диапазоном. Условия проверяются по порядку:

| Условие | Статус и причина |
| --- | --- |
| порт 53 (запись или диапазон) есть и в списке исключённых, и в списке перехватываемых портов | `failed` / `port_53_in_both_lists` |
| исключение выбрано, а в `port_proxying.lst` есть хотя бы одна действительная запись порта или диапазона | `failed` / `exclude_list_ignored`: при непустом списке перехватываемых портов установленный XKeen игнорирует список исключений целиком, выбранное исключение не действует |
| исключение выбрано и `proxy_dns="on"` | `failed` / `proxy_dns_contradicts_exclusion` |
| `proxy_dns` или `proxy_router` прочитан неоднозначно (`missing`, `duplicate`, `unexpected`, `unsupported`) | `unsupported` / `flags_unknown`: согласованность с флагами не оценить |
| иначе, в том числе когда исключение не выбрано | `passed` |

Противоречия проверяются раньше неизвестных флагов. Отсутствие исключения само по себе не ошибка и не доказательство перехвата: без выбранного исключения списки и флаги ему не противоречат. Для `proxy_router` правила противоречия нет — проверяется только его читаемость. Записи списков, кроме порта 53, с недопустимым содержимым XKeen отбрасывает, поэтому они не делают список перехватываемых портов непустым. Фактический путь DNS — отдельная сетевая проверка `dns_port_53_path`, всегда «не проверено». Проверка не несёт следующего шага и ничего не советует менять: факты списков показывают пункты 1 → 1 и 6 → 7, DNS и рабочие сайты через Pritunl проверяются раздельно.

## Представление

При успехе `data` — `QuickCheckView`:

| Поле | Содержимое |
| --- | --- |
| `active_network_check` | Признак активной сетевой проверки набора; всегда `False` |
| `outcome` | `QuickCheckOutcome`: `failed` — «найдены расхождения», хотя бы одна проверка `failed`; `incomplete` — «расхождений не найдено, часть проверок не выполнена или не поддерживается». Значения «всё успешно» нет: без сетевой проверки оно недостижимо, а итог, не согласованный с проверками, отклоняется конструктором |
| `counts` | Число проверок каждого статуса в порядке словаря: `passed`, `failed`, `not_checked`, `unsupported` |
| `sources` | Кортеж `SourceReadView` — по одному на источник в порядке чтения (`xray`, `settings`, `init`, `port_exclude`, `port_proxying`, `process`, `geodata`): `source` (`QuickCheckSource`), `state` (`SourceState`: `read`, `failed`, `not_connected`), `error` (`ErrorDetail` только при `failed`) |
| `checks` | `ChecksView` из девяти проверок в порядке `CHECK_ORDER` |

Модели проверяют точные типы: строка вместо `QuickCheckOutcome`, `QuickCheckSource`, `SourceState` или `CheckStatus` отклоняется; каждый источник и каждая проверка входят ровно один раз в своём порядке; `error` задан тогда и только тогда, когда источник отказал.

`to_dict()` возвращает JSON-совместимый словарь `{"active_network_check", "outcome", "counts", "sources", "checks"}`; источник — `{"source", "state", "error"}`, где `error` — словарь отказа со следующим шагом либо `null`; `checks` — словарь набора проверок `{"active_network_check", "items"}`. PID, теги, имена файлов, адреса, записи списков, значения параметров и текст исключений источников в представление не входят, модели источников недостижимы из результата. Русские подписи источников, итогов чтения и итога — таблицы `SOURCE_LABELS`, `SOURCE_STATE_LABELS` и `OUTCOME_LABELS` только для чтения: интерфейсы показывают их и не вычисляют итог и статусы. Команда и её представление добавлены в версии контракта 1 как совместимое расширение.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_application_quick_check.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_checks.py -v
python3 -I -S -B -m unittest discover -s tests -p 'test_cli_*.py' -v
```

Тесты используют [обезличенный снимок](../tests/fixtures/router_snapshot/README.md) для Xray и XKeen и искусственные наблюдения процесса, инвентари геобаз, списки, init, `xkeen.json` и части Xray. Проверяются девять проверок снимка и совпадение проверок областей с результатом сводки на тех же источниках, порядок и однократность чтения семи источников, отказ и некорректный ответ каждого источника только в его проверках без влияния на остальные и с описанием отказа один раз, неподключённые источники без вызовов, каждый статус каждой проверки, включая матрицы согласованности конфигурации Xray и режима порта 53, согласованность итога со счётчиками, точные типы и инварианты моделей, отсутствие PID, тегов, имён файлов и текста исключений в результате и отсутствие терминала, файлов, сети и процессов во время сценария. Роутер и сеть не требуются.
