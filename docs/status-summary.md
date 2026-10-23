# Сводка состояния по областям

Сценарий `InspectStatusSummary` из `keenvpn.application.status_summary` одним вызовом даёт раздельные состояния семи областей: ядро Xray, перехват, доступность VPN, DNS и порт 53, автозапуск, режим резерва и черновик. Его результат показывают шапка главного меню и пункт 1 → 1 «Сводка» [меню](cli-menu.md). Код работает в памяти: ничего не записывает, не запускает и не останавливает службы, не вызывает команды XKeen и init и не выполняет сетевых проб. Успех описывает снимок источников на момент чтения и не подтверждает работу VPN, перехват трафика или маршрут клиента.

## Прикладной сценарий

`InspectStatusSummary()` не имеет параметров, кроме версии контракта. `InspectStatusSummaryHandler(proxy, processes)` получает обработчик [чтения конфигурации Xray и XKeen](proxy-config.md#прикладной-сценарий) `InspectProxyConfigHandler` и порт `XrayProcessSource`. `None` вместо любого из них означает, что источник не подключён: сценарий его не вызывает, а зависящие от него области получают `not_checked` с причиной `source_not_connected`.

Источники читаются по одному разу в фиксированном порядке: части Xray, `xkeen.json`, параметры init, список исключённых портов, список перехватываемых портов — методом `read_source` обработчика конфигурации с его кодами отказов, затем наблюдение процесса — функцией `read_xray_process` с кодами [чтения установки](installation.md#прикладной-сценарий). Список исключённых адресов, состояние Keenetic и геобазы не читаются: ни одна область от них не зависит. Чтение и сборка разделены: `read_summary_sources(proxy, processes)` возвращает `SummaryReadings` — ответ каждого источника (модель либо `ErrorDetail`, `None` для неподключённого обработчика или источника) с `repr` без содержимого, `build_status_summary(readings)` собирает по ним представление; обработчик вызывает их по очереди, а [быстрая проверка](quick-check.md) строит по тем же ответам свои проверки без второго чтения. Проверка пути DNS области — функция `port_53_path_not_checked()`, общая с быстрой проверкой. Отказ или некорректный ответ одного источника не прерывает чтение остальных и не делает сценарий неуспешным: зависящие от него области получают `not_checked`, причину — код отказа источника (например, `xkeen_init_unavailable` или `invalid_xray_process`) и `source_error` — его описание с [безопасным следующим шагом](application.md#безопасный-следующий-шаг). Если у области несколько источников, указывается первый отказ в порядке чтения. Сценарий отказывает только при неверной команде (`invalid_request` / `invalid_command`) или версии контракта (`invalid_request` / `unsupported_contract_version`), не читая источников.

```python
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.status_summary import InspectStatusSummary, InspectStatusSummaryHandler
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet
from keenvpn.domain.xray_process import XrayProcessObservation


class FixedSources:
    """Искусственные данные; реальные файлы и процесс читают адаптеры роутера."""

    def current_xray_config(self):
        return XrayConfigSet((ConfigDocument("04_outbounds.json", b'{"outbounds": [{"tag": "proxy", "protocol": '
                                             b'"trojan"}, {"tag": "block", "protocol": "blackhole"}], "routing": '
                                             b'{"balancers": [{"tag": "group", "selector": ["proxy"], '
                                             b'"fallbackTag": "block"}]}}'),))

    def current_xkeen_settings(self):
        return XKeenSettings(ConfigDocument("xkeen.json", b'{"xkeen": {"killswitch": "on"}}'))

    def current_xkeen_init(self):
        return parse_xkeen_init(b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\n')

    def current_xkeen_list(self, name):
        return XKeenList(name, b"53\n" if name is XKeenListName.PORT_EXCLUDE else b"")

    def current_xray_process(self):
        return XrayProcessObservation((4242,), True)


sources = FixedSources()
handler = InspectStatusSummaryHandler(InspectProxyConfigHandler(sources, sources, sources, sources), sources)
result = handler.execute(InspectStatusSummary())
assert result.succeeded
assert [(item.area.value, None if item.state is None else item.state.value, item.check.status.value)
        for item in result.data.areas] == [
    ("core", "running", "passed"), ("interception", None, "unsupported"), ("vpn", None, "not_checked"),
    ("dns", "excluded", "not_checked"), ("autostart", "on", "passed"), ("fallback", "no_direct_fallback", "passed"),
    ("draft", None, "unsupported"),
]
assert "4242" not in str(result.to_dict())
unconnected = InspectStatusSummaryHandler(None, None).execute(InspectStatusSummary()).data
assert [item.check.reason for item in unconnected.areas if item.area.value == "core"] == ["source_not_connected"]
```

## Области

Статус каждой области — статус её проверки из [общего словаря](application.md#статусы-проверок); состояние — прочитанный факт источника, а не вывод об исправности. Статус `passed` возможен только при установленном состоянии, поэтому область без прочитанного источника исправной не бывает.

| Область | Источники | Состояние `AreaState` | Проверка | Статусы и причины |
| --- | --- | --- | --- | --- |
| `core` — ядро Xray | наблюдение процесса | `running`, `stopped`, `process_without_marker`, `marker_without_process`, `multiple_processes` | `xray_process_consistent` | `passed` для `running` и `stopped`, `failed` с состоянием в причине — как у [проверки сводки установки](installation.md#проверки-сводки); «успешно» подтверждает только согласованность процесса и ready-маркера |
| `interception` — перехват | нет | нет | `interception_active` | всегда `unsupported` / `interception_not_observed`: правила перехвата не читаются, а процесс и файлы перехват не доказывают |
| `vpn` — доступность VPN | нет | нет | `vpn_reachable`, сетевая | всегда `not_checked` / `network_check_not_performed` |
| `dns` — DNS и порт 53 | параметры init, списки исключённых и перехватываемых портов | `excluded`, `excluded_by_range`, `not_excluded` | `dns_port_53_path`, сетевая | всегда `not_checked` / `network_check_not_performed`: фактический путь DNS требует сетевой пробы |
| `autostart` — автозапуск | параметры init | `on`, `off` по флагу `start_auto` | `autostart_flag_unambiguous` | `passed` при `on` или `off`; `failed` / `flag_missing` — флага нет, `flag_duplicate` — повтор, в том числе с отступом, `flag_unexpected` — другое значение; `unsupported` / `flag_unsupported` — единственное присваивание с отступом или выражение. Запуск при загрузке не проверяется |
| `fallback` — режим резерва | `xkeen.json`, части Xray | `no_direct_fallback`, `direct_fallback` | `fallback_profile_consistent` | по [правилу режима резерва](#режим-резерва) |
| `draft` — черновик | нет | нет | `draft_present` | всегда `unsupported` / `drafts_not_implemented`: черновиков в этой версии нет |

Отказ или неподключённый источник меняют только области `core`, `dns`, `autostart` и `fallback`; у `interception`, `vpn` и `draft` источников нет, и их статус от подключения не зависит. Признак `active_network_check` всегда `False`: сетевые проверки областей `vpn` и `dns` не могут быть `passed` или `failed`, это проверяет набор проверок результата.

## Порт 53

Состояние области DNS — выбранное исключение по файлам: `excluded` — отдельная запись `53` в `port_exclude.lst`, `excluded_by_range` — порт 53 входит только в диапазон этого списка, `not_excluded` — нет ни того, ни другого. Это не вывод о фактическом перехвате: путь пакета зависит от правил netfilter, настроек Keenetic и приоритета списка перехватываемых портов в установленном XKeen, поэтому проверка пути DNS остаётся «не проверено». Отсутствие исключения само по себе не ошибка и не доказательство перехвата.

Факты области — поле `port_53`: `Port53View` с теми же полями, что [факты конфигурации XKeen](proxy-config.md#факты-по-порту-53) (записи и диапазоны в обоих списках, флаги `proxy_dns` и `proxy_router`); `None`, если источники области не прочитаны. Подсказка к выбору исключения — константа `PORT_53_HINT`: «Включение исключения оставляет TCP/UDP DNS на порту 53 вне прозрачного перехвата XKeen. Это может помочь при конфликте DNS, например при работе с Pritunl. Опция не открывает порт и не гарантирует исправление любой проблемы рабочего VPN.» Включение и выключение исключения в этой версии не реализованы.

## Режим резерва

Профиль определяется по двум значениям: флагу `killswitch` в `xkeen.json` и цели `fallbackTag` каждого балансировщика действующего раздела `routing`. Цель разрешает функция `balancer_fallbacks` [импорта правил](routing-import.md#назначение-и-действие) так же, как назначение правила: по действующим outbound всех частей. `freedom` и `direct` — прямой выход, `blackhole` и `block` — блокировка, протокол прокси или туннеля — VPN; отсутствующий или повторяющийся тег, цепочка через `proxySettings.tag` или `dialerProxy`, протокол без действия, неподдержанная структура балансировщика (не объект, тег не непустая строка, селектор не `StringList`, `fallbackTag` не строка, `strategy` не объект) и варианты регистра его полей — цель не определена.

| Условие, по порядку проверки | Статус и причина | Состояние |
| --- | --- | --- |
| `killswitch` отсутствует или не `on` и не `off` | `unsupported` / `killswitch_unknown` | нет |
| outbound, раздел `routing` или список балансировщиков не читаются однозначно | `unsupported` / `balancers_unsupported` | нет |
| `killswitch=on` и хотя бы один fallback ведёт к прямому выходу либо `killswitch=off` и хотя бы один ведёт к блокировке | `failed` / `fallback_profile_mismatch` | нет |
| балансировщиков нет | `unsupported` / `no_balancers` | нет |
| у балансировщика нет `fallbackTag`, цель не определена или цель — VPN | `unsupported` / `fallback_not_set`, `fallback_not_resolved` или `fallback_to_vpn` — первое найденное в этом порядке | нет |
| `killswitch=on`, все fallback ведут к блокировке | `passed` | `no_direct_fallback` |
| `killswitch=off`, все fallback ведут к прямому выходу | `passed` | `direct_fallback` |

Противоречие kill-switch и fallback важнее неопределённости остальных целей. Факты области — поле `fallback`: `FallbackView` с флагом `killswitch` (статус и значение), числом балансировщиков `balancer_count` и числом целей по видам `direct_count`, `blocked_count`, `vpn_count`, `unresolved_count`, `unset_count` без тегов. Счётчики — `None`, если балансировщики не читаются однозначно; весь блок — `None`, если источники области не прочитаны. Профиль описывает настройку, а не доступность: успешный прямой выход или резерв не делают VPN проверенным.

## Представление

При успехе `data` — `StatusSummaryView`:

| Поле | Содержимое |
| --- | --- |
| `active_network_check` | Признак активной сетевой проверки; у сводки всегда `False` |
| `areas` | Кортеж `SummaryAreaView` — по одной на область в порядке таблицы областей: `area` (`SummaryArea`), `state` (`AreaState` или `None`), `check` (`CheckView`), `source_error` (`ErrorDetail` или `None`) |
| `port_53` | `Port53View` или `None` |
| `fallback` | `FallbackView` или `None` |
| `checks` | `ChecksView` из проверок всех областей: проверяет признак активной проверки и инвариант пассивного результата; в `to_dict()` не входит |

Модели проверяют точные типы: строка вместо `SummaryArea`, `AreaState` или `CheckStatus` отклоняется. Состояние должно входить в набор своей области (`AREA_STATES`), код и признак сети проверки — совпадать с заданными для области, `passed` требует установленного состояния, а `source_error` — статуса `not_checked`, пустого состояния и причины, равной коду отказа. Факты порта 53 есть тогда и только тогда, когда состояние области DNS установлено, факты резерва — когда прочитаны его источники.

`to_dict()` возвращает JSON-совместимый словарь `{"active_network_check", "areas", "port_53", "fallback"}`; область — `{"area", "state", "check", "source_error"}`, где `check` — словарь проверки `{"code", "status", "network", "reason"}`, а `source_error` — словарь отказа со следующим шагом либо `null`. PID, теги, имена файлов, адреса, значения параметров и текст исключений источников в представление не входят, модели источников недостижимы из результата. Русские подписи областей и состояний — таблицы `AREA_LABELS` и `STATE_LABELS` только для чтения: интерфейсы показывают их и не вычисляют состояния и статусы. Команда и её представление добавлены в версии контракта 1 как совместимое расширение.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_application_status_summary.py -v
python3 -I -S -B -m unittest discover -s tests -p test_routing_import.py -v
python3 -I -S -B -m unittest discover -s tests -p 'test_cli_*.py' -v
```

Тесты используют [обезличенный снимок](../tests/fixtures/router_snapshot/README.md) для Xray и XKeen и искусственные наблюдения процесса, списки, init, `xkeen.json` и части Xray. Проверяются семь областей снимка, порядок и однократность чтения источников, отказ и некорректный ответ каждого источника без влияния на чужие области и на чтение остальных, неподключённые источники без вызовов, каждое состояние и каждый статус каждой области, матрица режима резерва, точные типы и инварианты моделей, отсутствие PID, тегов, имён файлов и текста исключений в результате и отсутствие терминала, файлов, сети и процессов во время сценария. Роутер и сеть не требуются.
