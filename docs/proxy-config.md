# Чтение конфигурации Xray и XKeen

`keenvpn.domain.config_document`, `keenvpn.domain.xray_config` и `keenvpn.domain.xkeen_config` описывают прочитанные файлы прозрачного прокси: части конфигурации Xray, `xkeen.json`, параметры стартового сценария XKeen и три списка портов и адресов. Сценарий `InspectProxyConfig` читает их через раздельные источники и возвращает структурную сводку без секретов. Код работает в памяти: он не обращается к роутеру, не запускает Xray, не вызывает команды XKeen, не исполняет init и ничего не записывает. Успех описывает снимок файлов на момент чтения, а не работу VPN, перехват трафика или маршрут клиента.

## Документ конфигурации

`ConfigDocument(name, content)` принимает имя файла без каталога и его байты. Имя — печатная строка до 255 символов без `/`, `\`, пробелов по краям и без начальной точки. Содержимое должно быть текстом UTF-8; размер (`size`) и `sha256` относятся к исходным байтам вместе с комментариями и переводами строк.

Разбор строгий: поддерживаются `//` и `/* */` вне строк. Закрытый блочный комментарий заменяется пробельным разделителем с сохранением переводов строк, поэтому токены по разные стороны любого блока не склеиваются. Незакрытый блок отклоняется, в том числе после завершённого объекта. Затем текст читается как JSON-объект. Повтор ключа на любом уровне, `NaN`, `Infinity`, бесконечные числа, массив или скаляр на верхнем уровне, BOM, комментарии `#` и вложенность свыше 64 уровней отклоняются кодом `invalid_document_json`. `export()` возвращает новую копию разобранного объекта для доверенного кода и не является безопасным выводом; `sections` и `to_diagnostic()` содержат только имя, ревизию и имена полей верхнего уровня. `validate_config_document(document)` заново строит документ по его байтам и отклоняет подмену хеша, снимка или содержимого.

| Код `ConfigDocumentErrorCode` | Причина |
|---|---|
| `invalid_document_name` | Имя не строка, пустое, слишком длинное, с разделителем пути, пробелами по краям или начальной точкой |
| `invalid_document_content` | Содержимое не `bytes` либо не текст UTF-8 |
| `invalid_document_json` | Текст не является строгим JSON-объектом |
| `invalid_config_document` | Модель другого типа или повреждена после создания |

## Конфигурация Xray

`XrayConfigSet(parts)` хранит части в порядке источника с уникальными именами; пустой набор допустим. Адаптер `keenvpn.adapters.xray_configs.xray_config_from_files(files)` собирает набор из словаря «имя → байты», упорядочивая части по имени, как при загрузке каталога конфигураций. Отбор файлов `*.json` выполняет источник при перечислении каталога `XRAY_CONFIG_DIRECTORY`; чтение файлов на роутере с ограничением размера описано в [источниках чтения роутера](router-sources.md).

`to_diagnostic()` и `summarize_xray_config(parts)` строят структурную сводку за один проход по частям. Строки из файлов попадают в неё только по правилу [безопасного вывода](#безопасный-вывод-сводки): теги и селекторы — после проверки формата, протоколы, стратегии, `type` правила, имена полей условий и разделов — только из списков известных значений Xray; скрытое значение заменяется на `None`.

| Поле | Содержимое |
|---|---|
| `part_count`, `parts` | Имя, размер, SHA-256, известные разделы верхнего уровня (`sections`) и число остальных (`unknown_section_count`) каждой части; `summarize_xray_config` даёт имя и разделы, ревизию добавляет `to_diagnostic()` набора |
| `sections`, `duplicate_sections` | Какие части содержат каждый известный раздел верхнего уровня; известные разделы, встречающиеся более чем в одной части |
| `dns_tags`, `domain_strategies` | `dns.tag` после проверки формата и известные `routing.domainStrategy` из всех частей в порядке частей; скрытое значение — `None` на своей позиции |
| `inbounds`, `outbounds` | Часть, индекс в своём списке (`index`), `tag` после проверки формата и известный `protocol` каждого элемента; `tag_known` и `protocol_known` показывают, было ли строковое поле в файле |
| `duplicate_inbound_tags`, `duplicate_outbound_tags`, `duplicate_balancer_tags` | Теги, встречающиеся более одного раза, после проверки формата; повтор считается по исходным значениям |
| `rule_count`, `rules` | Для каждого правила: часть, индекс, известный `type` с `type_known`, ссылки `inboundTag` после проверки формата и их разрешимость, назначение `outbound`/`balancer`/`both`/`none` с тегом (`target_tag`, `target_tag_known`), разрешимостью и позицией цели (`target_position`), наличие `ruleTag`, число значений каждого известного поля условия (`conditions`) и число полей, которые декодер Xray не читает (`unknown_condition_count`) |
| `balancers` | Часть, индекс, тег с `tag_known`, `selector` после проверки формата, число outbound с таким префиксом, `fallbackTag` с `fallback_known`, разрешимостью и позицией цели (`fallback_position`), известный тип `strategy` с `strategy_known` |
| `observatory_subjects` | Селекторы `subjectSelector` разделов `observatory` и `burstObservatory` после проверки формата и число совпавших outbound |
| `unsupported_paths` | Места частей, структура которых не поддержана сводкой: например `inbounds[1]` или `routing.rules[4].inboundTag`; пути собираются из фиксированных имён полей и индексов |

Поля `inboundTag` правил и `selector` балансировщиков принимают массив строк либо строку с разделением по запятым, как `StringList` Xray. Пробелы и пустые элементы строковой формы сохраняются; запятые внутри элементов массива не разделяются. `subjectSelector` разделов `observatory` и `burstObservatory` принимает только массив строк. Общий декодер `decode_string_list(value)` возвращает кортеж строк либо `None` для значения, которое декодер Xray отклонит; перевод действующего раздела `routing` в группы условий и политику маршрутизации описан в [импорте правил](routing-import.md).

Тот же проход собирает значения списков доменов и адресов правил (`domain`, `domains`, `ip`, `source`, `sourceIP`, `localIP`), серверов DNS (`domains`, `expectIPs`, `expectedIPs`, `unexpectedIPs`) и ключи `dns.hosts`: `rule_list_values(parts)` и `XrayConfigSet.rule_list_values()` возвращают их как `RuleListValue` для доверенного кода с выбором алиасов `source`/`sourceIP` и `expectIPs`/`expectedIPs` по правилам Xray, например для [разбора ссылок на наборы геобаз](installation.md#ссылки-на-наборы-из-конфигурации-xray). В сводку эти значения не входят; поле списка другого типа, элемент не строка, `servers` не список, сервер не объект и не строка, `hosts` не объект отмечаются в `unsupported_paths`.

Ссылка `inboundTag` считается разрешённой, если тег есть среди inbound, равен `dns.tag` или непустому тегу отдельного сервера `dns.servers[].tag`: Xray использует такой тег как inbound-тег запросов сервера, а пустой тег равен отсутствующему; сами теги серверов в сводку не входят. Селекторы балансировщиков и наблюдателя сопоставляются по префиксу тега outbound, как в Xray; пустой селектор совпадает со всеми тегами. Правило с `outboundTag` и `balancerTag` одновременно или без обоих отмечается как `both`/`none` с неразрешённым назначением; сводка не выбирает одно из них. Пустая строка в `outboundTag`, `balancerTag` и `fallbackTag` считается отсутствующим значением, как в Xray: правило только с пустыми назначениями — `none`, пустой `fallbackTag` — резерв не задан. Разрешимость ссылок, совпадения селекторов и повторы считаются по исходным тегам до проверки формата. Объединение разделов между частями не моделируется, установленный Xray для проверки не вызывается.

Позиция элемента — часть и индекс в своём списке: `inbounds[i]`, `outbounds[i]` или `routing.balancers[i]` той части, как в путях `unsupported_paths`. `target_position` правила и `fallback_position` балансировщика заполняются, только если среди всех частей ровно один outbound (для назначения `outbound` и `fallbackTag`) или ровно один балансировщик (для назначения `balancer`) носит этот тег; при отсутствии или повторе тега позиция — `None`, хотя `target_resolved` и `fallback_resolved` при повторе остаются истинными. По позиции можно отличить два элемента со скрытыми тегами и определить, какой из них выбран правилом или `fallbackTag`.

В сводку входят только теги, протоколы, имена полей и счётчики. Значения `settings` и `streamSettings`, домены, адреса, порты, пути, пароли, UUID, ключи REALITY и теги правил `ruleTag` в неё не попадают; `repr()` набора показывает только число частей. Структура, не соответствующая ожидаемой (раздел не список, элемент не объект, поле другого типа), отмечается в `unsupported_paths`, а не исправляется и не прерывает чтение.

## Безопасный вывод сводки

Теги, селекторы, имена полей и разделов задаёт пользователь, поэтому сводка и [импорт правил](routing-import.md#безопасный-вывод) выводят их по одному правилу из общего модуля `keenvpn.domain.xray_identifiers`:

| Значение | Проверка | Функция |
|---|---|---|
| Теги inbound, outbound и балансировщиков, `dns.tag`, `inboundTag`, `outboundTag`, `balancerTag`, `fallbackTag`, списки повторов | Формат технического идентификатора: до 128 символов из букв ASCII, цифр, `_`, `+` и `-`, начиная с буквы или цифры; всё, что разбирается как IP-адрес, скрывается | `safe_identifier` |
| `selector` балансировщика, `subjectSelector` | То же; пустой селектор показывается пустым | `safe_selector` |
| `strategy.type` | Известные стратегии `random`, `leastPing`, `roundRobin`, `leastLoad` без учёта регистра | `safe_strategy` |
| `routing.domainStrategy` | `AsIs`, `IPIfNonMatch`, `IPOnDemand` без учёта регистра | `safe_domain_strategy` |
| `protocol` inbound | Ключи загрузчика inbound: `tunnel`, `dokodemo-door`, `http`, `shadowsocks`, `mixed`, `socks`, `vless`, `vmess`, `trojan`, `wireguard`, `hysteria`, `tun`; без учёта регистра | `safe_inbound_protocol` |
| `protocol` outbound | Ключи загрузчика outbound: `block`, `blackhole`, `loopback`, `direct`, `freedom`, `http`, `shadowsocks`, `socks`, `vless`, `vmess`, `trojan`, `hysteria`, `dns`, `wireguard`; без учёта регистра | `safe_outbound_protocol` |
| `type` правила | Только `field` | `safe_rule_type` |
| Имена полей условий правила | Только поля `parseFieldRule` (`XRAY_RULE_CONDITION_FIELDS`), остальные учитываются числом | `known_condition_field` |
| Разделы верхнего уровня части | Только разделы структуры `Config` (`XRAY_SECTIONS`): `log`, `api`, `dns`, `routing`, `policy`, `inbounds`, `outbounds`, `transport`, `stats`, `reverse`, `fakeDns`, `metrics`, `observatory`, `burstObservatory`, `version`; остальные учитываются числом | `known_section` |

Списки известных значений сверены с исходниками Xray-core тега `XRAY_VERSION` (`v26.3.27`): `infra/conf/xray.go`, `router.go`, `loader.go`. Сравнение без учёта регистра повторяет загрузчик Xray и выполняется только для строк ASCII: строка с не-ASCII символами скрывается, даже если приведение регистра свело бы её к известному имени (например, знак Кельвина U+212A в `soc\u212As`). Имена разделов и полей сравниваются точно, хотя JSON-декодер Go принял бы их и в другом регистре, — такой раздел или поле сводка считает неизвестным. Любое другое значение `domainStrategy` Xray трактует как `AsIs`; сводка его скрывает, а не подменяет.

Скрытое значение заменяется на `None`, а признак `*_known` (`tag_known`, `protocol_known`, `type_known`, `target_tag_known`, `fallback_known`, `strategy_known`) показывает, что строковое значение в файле было: `known=False` означает отсутствие или поле другого типа, `known=True` с `None` — скрытое значение. В списках скрытый элемент стоит на своей позиции, поэтому длина и порядок сохраняются. Исходные значения остаются доверенному коду в `export()` частей и `rule_list_values()`.

Остаточное ограничение: проверка формата не отличает секрет, составленный только из букв ASCII, цифр, `_`, `+` и `-`, от тега — такой секрет будет показан как тег, поэтому секреты в тегах, селекторах и ключах `xkeen.json` хранить не следует. Домены, адреса, пароли и пути в сводку не входят независимо от этой проверки.

| Код `XrayConfigErrorCode` | Причина |
|---|---|
| `invalid_xray_parts` | Части не кортеж документов либо имена повторяются; то же для не-словаря в `xray_config_from_files` |
| `invalid_xray_config` | Набор другого типа или повреждён после создания |

`validate_xray_config_set(config)` проверяет набор и каждую часть по её байтам; ошибка документа проходит наружу своим кодом.

## Настройки XKeen

`XKeenSettings(document)` хранит `xkeen.json` целиком и принимает только документ с этим точным именем (`XKEEN_SETTINGS_NAME`). `validate_xkeen_settings(settings)` повторно проверяет имя и целостность документа: другой файл или подмена документа после создания модели отклоняются до построения сводки. `settings_keys` возвращает имена полей объекта `xkeen`, `killswitch` — флаг `XKeenFlag`:

| `status` (`XKeenFlagStatus`) | Основание |
|---|---|
| `present` | Строка `"on"` или `"off"`; значение в `value` |
| `missing` | Нет объекта `xkeen` или поля `killswitch` |
| `unsupported` | Объект `xkeen` или поле другого типа |
| `unexpected` | Строка с другим значением |

XKeen считает включённым только строковое `"on"`; модель не подменяет другие значения выключенным состоянием, а показывает их статус. В `to_diagnostic()` имена разделов верхнего уровня и полей объекта `xkeen` показываются только в формате технического идентификатора (`safe_identifier` из [правила безопасного вывода](#безопасный-вывод-сводки)), остальные учитываются счётчиками `hidden_section_count` и `hidden_settings_key_count`; свойство `settings_keys` по-прежнему возвращает все имена доверенному коду. `keenvpn.adapters.xkeen_files.xkeen_settings_from_bytes(content)` создаёт модель из байтов файла под именем `xkeen.json`.

## Параметры init

Стартовый сценарий читается построчно как данные, без исполнения и `source`. `parse_xkeen_init(content)` учитывает строки вида `name=...` после необязательных пробелов — так же их ищет штатная функция переключения флагов XKeen. Условия, функции, heredoc, `export` и `local` не разбираются: строка внутри heredoc тоже становится присваиванием, а `export name="on"` не учитывается. Завершающий `\r` отбрасывается.

Каждое `XKeenInitAssignment` хранит имя, правую часть как написана (`raw`), номер строки и признак отступа. Форма считается поддержанной (`literal`), если правая часть — одно значение в двойных кавычках без `$`, обратных кавычек, экранирования и хвоста после закрывающей кавычки; только тогда доступно `value`. Присваивание с отступом — обычно внутри функции — не входит в `parameter_names`, но учитывается при определении статуса: отступ не доказывает контекст функции, а такая строка может переопределить значение.

`XKeenInitParameters.parameter(name)` возвращает статус имени по всем его присваиваниям, ничего не выбирая по первому:

| `status` | Основание |
|---|---|
| `present` | Ровно одно присваивание имени, без отступа и в поддержанной форме |
| `missing` | Присваиваний нет |
| `duplicate` | Два и более присваивания имени, включая присваивания с отступом; значение не выбирается |
| `unsupported` | Единственное присваивание имени в неподдержанной форме либо с отступом |

`switch(name)` дополнительно сводит значение к `on`/`off`: поддержанное значение другого вида даёт `unexpected`. `to_diagnostic()` содержит счётчики присваиваний (`assignment_count`, `top_level_count`, `indented_count`, `literal_count`, `expression_count`, `parameter_count`), отсортированные имена со статусом `duplicate` и флаги `start_auto`, `proxy_dns`, `proxy_router`, `ipv6_support` со статусом, значением `on`/`off` и числом присваиваний с отступом. Значения остальных параметров в вывод не входят.

`xkeen_init_from_bytes(content)` разбирает текст, `xkeen_init_from_flags(flags)` собирает параметры из уже извлечённых значений: каждый флаг становится единственным присваиванием без номера строки. Обезличенный снимок содержит только извлечённые флаги, поэтому разбор текста проверяется на синтетическом тексте.

`validate_xkeen_init(init)` заново проверяет поля каждого вложенного присваивания и порядок номеров строк. Повреждённая модель отклоняется кодом `invalid_xkeen_init` до построения диагностики; прикладной сценарий возвращает `invalid_source_data` без частичного результата.

## Списки XKeen

`XKeenList(name, content)` принимает `XKeenListName` (`port_exclude.lst`, `port_proxying.lst`, `ip_exclude.lst`) и байты файла; исходный текст сохраняется в `text`. Строки разбираются по правилам установленного init: `#` начинает комментарий до конца строки, пробелы по краям и завершающий `\r` не учитываются. `lines` возвращает строки с видом `blank`/`comment`/`entry`, `items` — элементы записей:

| Список | Элемент записи |
|---|---|
| Порты | Запись делится по запятым; `a:b` и `a-b` — диапазон (границы упорядочиваются), число 1–65535 — порт (ведущие нули допустимы, значение сравнивается как число), остальное — `invalid` |
| Адреса | Токены через пробелы, запятые и `;`; адрес или сеть по `ipaddress` — `address`, остальное — `invalid`; значения не нормализуются |

`lists_port(port)` проверяет отдельную запись порта, `covers_port_by_range(port)` — попадание в диапазон. `to_diagnostic()` содержит имя и счётчики строк и элементов без значений; `port_count`/`range_count` заполнены только для списков портов, `address_count` — только для списка адресов. `xkeen_list_from_bytes(name, content)` создаёт модель; имена файлов и каталог заданы `XKEEN_LIST_DIRECTORY`.

## Факты по порту 53

`port_53_facts(init, port_exclude, port_proxying)` и `XKeenConfig.port_53` возвращают `Port53Facts` с раздельными фактами: отдельная запись `53` в `port_exclude.lst`, попадание в диапазон этого списка, отдельная запись и диапазон в `port_proxying.lst`, флаги `proxy_dns` и `proxy_router` из init. Это не вывод о фактическом перехвате DNS: путь пакета зависит от правил netfilter, настроек Keenetic и приоритета списка перехватываемых портов в установленном XKeen. Отсутствие записи не является ошибкой и не меняется чтением.

`assemble_xkeen_config(settings, init, port_exclude, port_proxying, ip_exclude)` собирает `XKeenConfig`; имена списков должны соответствовать полям, иначе `invalid_xkeen_config`. `validate_xkeen_config(config)` заново проверяет все модели.

| Код `XKeenConfigErrorCode` | Причина |
|---|---|
| `invalid_xkeen_settings` | Настройки не `ConfigDocument`/`XKeenSettings`, имя документа не `xkeen.json` или модель повреждена |
| `invalid_xkeen_init` | Init не байты UTF-8, присваивания неверного типа или с несогласованными номерами строк, недопустимое имя параметра, некорректные извлечённые флаги |
| `invalid_xkeen_list` | Имя не `XKeenListName`, содержимое не байты UTF-8 или модель повреждена |
| `invalid_xkeen_config` | Несогласованный флаг или факты, список с другим именем, собранные настройки другого типа |

## Прикладной сценарий

`InspectProxyConfig()` не имеет параметров, кроме версии контракта. `InspectProxyConfigHandler(xray, settings, init, lists)` получает четыре порта `application.ports`:

| Порт | Метод | Файлы | Модель |
|---|---|---|---|
| `XrayConfigSource` | `current_xray_config()` | `*.json` каталога конфигураций Xray | `XrayConfigSet` |
| `XKeenSettingsSource` | `current_xkeen_settings()` | `xkeen.json` | `XKeenSettings` |
| `XKeenInitSource` | `current_xkeen_init()` | `S05xkeen` как текст | `XKeenInitParameters` |
| `XKeenListSource` | `current_xkeen_list(name)` | `port_exclude.lst`, `port_proxying.lst`, `ip_exclude.lst` | `XKeenList` |

Источники вызываются по одному разу в фиксированном порядке: части Xray, настройки, init, список исключённых портов, список перехватываемых портов, список исключённых адресов. После отказа или некорректного ответа следующие источники не читаются; частичного результата нет. Метод `read()` обработчика выполняет то же чтение и возвращает `ProxyConfigModels` (набор частей Xray и собранные настройки XKeen) для доверенного кода либо `ErrorDetail` с теми же кодами; его использует [чтение существующей установки](installation.md).

Метод `read_source(source)` читает один источник: `source` — член `ProxyConfigSource` (`xray`, `settings`, `init`, `port_exclude`, `port_proxying`, `ip_exclude`; порядок членов — порядок чтения), строка или другой тип отклоняются `TypeError`. Источник вызывается один раз, ответ проверяется так же, как в сценарии; результат — модель источника либо `ErrorDetail` с кодом этого источника из таблицы ниже, включая `xkeen_list_name_mismatch` в `reason`. `read()` читает источники этим методом и останавливается на первом отказе, [сводка состояния](status-summary.md) и [быстрая проверка](quick-check.md) читают нужные им источники по одному и продолжают после отказа.

```python
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler, XrayPositionView
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet


class FixedSources:
    """Искусственные данные; реальные файлы читает адаптер роутера."""

    def current_xray_config(self):
        return XrayConfigSet((
            ConfigDocument("04_outbounds.json", b'{"outbounds": [{"tag": "proxy-out", "protocol": "trojan", '
                           b'"settings": {"servers": [{"address": "vpn.example.test", "password": "TEST_ONLY"}]}}]}'),
            ConfigDocument("05_routing.json", b'{"routing": {"rules": [{"type": "field", "network": "tcp,udp", '
                           b'"outboundTag": "proxy-out"}]}}'),
        ))

    def current_xkeen_settings(self):
        return XKeenSettings(ConfigDocument("xkeen.json", b'{"xkeen": {"killswitch": "on"}}'))

    def current_xkeen_init(self):
        return parse_xkeen_init(b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\nipv6_support="on"\n')

    def current_xkeen_list(self, name):
        return XKeenList(name, b"53\n" if name is XKeenListName.PORT_EXCLUDE else b"")


sources = FixedSources()
result = InspectProxyConfigHandler(sources, sources, sources, sources).execute(InspectProxyConfig())
assert result.succeeded
assert [part.name for part in result.data.xray.parts] == ["04_outbounds.json", "05_routing.json"]
assert result.data.xray.outbounds[0].protocol == "trojan"
assert result.data.xray.rules[0].target_resolved is True
assert result.data.xray.rules[0].target_position == XrayPositionView("04_outbounds.json", 0)
assert result.data.xkeen.settings.killswitch.value == "on"
assert result.data.xkeen.port_53.port_exclude_entry is True
assert "vpn.example.test" not in str(result.data.to_dict())
```

При успехе `data` — `ProxyConfigView` с двумя частями:

| Поле | Содержимое |
|---|---|
| `xray` | `XrayConfigView`: те же поля, что в сводке набора частей; `parts` — кортеж `XrayPartView` с `unknown_section_count`, `inbounds`/`outbounds` — кортежи `XrayEndpointView(part, index, tag_known, tag, protocol_known, protocol)`, `rules[].conditions` — кортеж `XrayConditionView(key, value_count)`, `rules[].target_position` и `balancers[].fallback_position` — `XrayPositionView(part, index)` либо `None`, `sections` — кортеж `XraySectionView(name, parts)` |
| `xkeen.settings` | `XKeenSettingsView`: имя, размер, SHA-256, разделы после проверки формата и `hidden_section_count`, `has_xkeen_section`, `settings_keys` после проверки формата и `hidden_settings_key_count`, `killswitch` |
| `xkeen.init` | `XKeenInitView`: счётчики, `duplicate_names`, `flags` — кортеж `XKeenInitFlagView(name, status, value, indented_count)` |
| `xkeen.port_exclude`, `xkeen.port_proxying`, `xkeen.ip_exclude` | `XKeenListView` со счётчиками строк и элементов |
| `xkeen.port_53` | `Port53View`: порт, четыре признака записей и флаги `proxy_dns`, `proxy_router`; `Port53View.from_facts(facts)` строит его из `Port53Facts`, `to_dict()` даёт словарь с флагами `{status, value}` |

Имена файлов проверяет `valid_document_name`; теги, протоколы, стратегии, имена разделов и ключи `xkeen.json` — значения из файлов, а не доверенные идентификаторы: они показываются только после проверки формата или по списку известных значений Xray по [правилу безопасного вывода](#безопасный-вывод-сводки), скрытое значение — `None` с признаком `*_known`. Домены, адреса, порты слушателей, пути, пароли, теги правил, значения параметров init и записи списков в представление не входят; модели источников недостижимы из результата. `to_dict()` возвращает JSON-совместимый словарь (`sections`, `conditions` и `flags` — словари по именам, позиции — словари `{part, index}`), представление одного результата не читает источники повторно.

| Ситуация | Категория и код |
|---|---|
| Неверный тип команды | `invalid_request` / `invalid_command` |
| Неверная версия команды | `invalid_request` / `unsupported_contract_version` |
| Источник вызвал исключение | `source_failed` / `xray_config_unavailable`, `xkeen_settings_unavailable`, `xkeen_init_unavailable`, `xkeen_port_exclude_unavailable`, `xkeen_port_proxying_unavailable` или `xkeen_ip_exclude_unavailable` |
| Источник вернул объект другого типа, включая подкласс | `invalid_source_data` / `invalid_xray_config`, `invalid_xkeen_settings`, `invalid_xkeen_init`, `invalid_xkeen_port_exclude`, `invalid_xkeen_port_proxying` или `invalid_xkeen_ip_exclude`; `reason=None` |
| Модель повреждена после создания | тот же код источника; доменная причина в `reason` |
| Список вернулся с другим именем | тот же код источника; `reason=xkeen_list_name_mismatch` |
| Модели не удалось собрать | `invalid_source_data` / `proxy_config_inconsistent`; доменная причина в `reason` |

Текст и цепочка исключений источников в результат не попадают, `KeyboardInterrupt` и `SystemExit` проходят наружу. Успех означает только согласованное чтение переданных файлов: он не подтверждает принятие конфигурации Xray, работу XKeen, фактический перехват DNS, kill-switch или VPN и не меняет роутер.

## Список подключений

`InspectConnections()` не имеет параметров, кроме версии контракта. `InspectConnectionsHandler(proxy)` принимает обработчик `InspectProxyConfigHandler`, читает источники его методом `read()` — тот же порядок, те же коды отказов, без частичного результата — и строит `ConnectionsView` из `XrayConfigView` тех же моделей: домен не читается повторно и ничего не вычисляет заново.

```python
from keenvpn.application.proxy_config import InspectProxyConfigHandler, XrayPositionView
from keenvpn.application.proxy_connections import InspectConnections, InspectConnectionsHandler
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet


class FixedSources:
    """Искусственные данные; реальные файлы читает адаптер роутера."""

    def current_xray_config(self):
        return XrayConfigSet((
            ConfigDocument("04_outbounds.json", b'{"outbounds": [{"tag": "proxy-out", "protocol": "trojan", '
                           b'"settings": {"servers": [{"address": "vpn.example.test", "password": "TEST_ONLY"}]}}, '
                           b'{"tag": "direct", "protocol": "freedom"}]}'),
            ConfigDocument("05_routing.json", b'{"routing": {"balancers": [{"tag": "pool", "selector": ["proxy-"], '
                           b'"fallbackTag": "direct", "strategy": {"type": "leastPing"}}]}}'),
        ))

    def current_xkeen_settings(self):
        return XKeenSettings(ConfigDocument("xkeen.json", b'{"xkeen": {"killswitch": "on"}}'))

    def current_xkeen_init(self):
        return parse_xkeen_init(b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\nipv6_support="on"\n')

    def current_xkeen_list(self, name):
        return XKeenList(name, b"53\n" if name is XKeenListName.PORT_EXCLUDE else b"")


sources = FixedSources()
proxy = InspectProxyConfigHandler(sources, sources, sources, sources)
result = InspectConnectionsHandler(proxy).execute(InspectConnections())
assert result.succeeded
view = result.data
assert (view.outbound_count, view.balancer_count, view.hidden_tag_count) == (2, 1, 0)
assert [item.kind.value for item in view.connections] == ["outbound", "outbound", "balancer"]
assert (view.connections[0].tag, view.connections[0].protocol) == ("proxy-out", "trojan")
assert view.connections[2].fallback_position == XrayPositionView("04_outbounds.json", 1)
assert "vpn.example.test" not in str(view.to_dict()) and "TEST_ONLY" not in str(view.to_dict())
```

`ConnectionsView`:

| Поле | Содержимое |
|---|---|
| `part_count`, `outbound_count`, `balancer_count` | Число частей набора, outbound и балансировщиков во всех частях |
| `duplicate_outbound_tag_count`, `duplicate_balancer_tag_count` | Число повторяющихся тегов по исходным значениям, как в сводке |
| `hidden_tag_count` | Число элементов, чей тег задан, но скрыт как небезопасный |
| `connections` | Кортеж: сначала все outbound в порядке частей и индексов сводки, затем все балансировщики; номер элемента в меню — его позиция здесь, начиная с 1 |

Элемент `OutboundConnectionView`: `kind` (`outbound`), `position` — `XrayPositionView(part, index)`, `tag_known`, `tag`, `protocol_known`, `protocol`. Элемент `BalancerConnectionView`: `kind` (`balancer`), `position`, `tag_known`, `tag`, `selector` (скрытый селектор — `None` на своей позиции, пустой — `""`), `selector_match_count`, `fallback_known`, `fallback_tag`, `fallback_resolved`, `fallback_position`, `strategy_known`, `strategy`. Значения те же, что у `XrayEndpointView` и `XrayBalancerView` сводки, по [правилу безопасного вывода](#безопасный-вывод-сводки): скрытое значение — `None` с признаком `*_known`, поэтому два outbound со скрытыми тегами различаются только позицией. Вид действия outbound (прямой выход, блокировка, VPN) в список не входит: по одному протоколу без разрешателя [импорта правил](routing-import.md) его нельзя определить безопасно — outbound `freedom` с `proxySettings` или `dialerProxy` передаёт соединение дальше. Адреса серверов, порты, идентификаторы, пароли, SNI, пути и ссылки не читаются, разбор ссылок не выполняется, поля настроек outbound не учитываются даже по именам. `to_dict()` возвращает JSON-совместимый словарь, где каждый элемент несёт `kind`, а позиции — словари `{part, index}`. Коды отказов — коды `InspectProxyConfig` без изменения плюс `invalid_command` и `unsupported_contract_version`. Успех не подтверждает доступность подключений, работу Xray, XKeen или VPN.

## Ошибки домена

`ConfigDocumentError`, `XrayConfigError` и `XKeenConfigError` содержат машинный `code` и фиксированный текст без имён файлов, содержимого и значений. Активное чужое исключение не сохраняется в `__context__` и `__cause__`.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_config_document.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xray_config.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xray_identifiers.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xkeen_config.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xkeen_files.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_proxy_config.py -v
```

Тесты используют искусственные части, синтетический текст init и [обезличенный снимок](../tests/fixtures/router_snapshot/README.md), из которого `tests/support/snapshot.py` собирает модели и управляемые источники; SHA-256 частей Xray совпадают с `manifest.json` снимка. Проверяются строгий JSON с комментариями и без, ссылки между тегами, неподдержанные структуры, повторы и неподдержанный синтаксис init, разбор списков, факты по порту 53, отказ каждого источника, отсутствие секретов в результатах, скрытие искусственных небезопасных тегов, протоколов, стратегий и имён полей (URI с паролем, адреса, домен, путь, userinfo, управляющие символы, не-ASCII, строка длиннее 128 символов) с признаками `*_known` и позициями, списки известных значений Xray и отсутствие терминала, файлов, сети и процессов во время сценария. Роутер и сеть не требуются.
