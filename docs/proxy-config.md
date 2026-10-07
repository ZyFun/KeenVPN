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

`XrayConfigSet(parts)` хранит части в порядке источника с уникальными именами; пустой набор допустим. Адаптер `keenvpn.adapters.xray_configs.xray_config_from_files(files)` собирает набор из словаря «имя → байты», упорядочивая части по имени, как при загрузке каталога конфигураций. Отбор файлов `*.json` выполняет источник при перечислении каталога `XRAY_CONFIG_DIRECTORY`; транспорт и ограничение размера файла в репозитории не реализованы.

`to_diagnostic()` и `summarize_xray_config(parts)` строят структурную сводку за один проход по частям:

| Поле | Содержимое |
|---|---|
| `part_count`, `parts` | Имя, размер, SHA-256 и имена разделов каждой части |
| `sections`, `duplicate_sections` | Какие части содержат каждый раздел верхнего уровня; разделы, встречающиеся более чем в одной части |
| `dns_tags`, `domain_strategies` | `dns.tag` и `routing.domainStrategy` из всех частей |
| `inbounds`, `outbounds` | Часть, `tag` и `protocol` каждого элемента; отсутствующее поле — `None` |
| `duplicate_inbound_tags`, `duplicate_outbound_tags`, `duplicate_balancer_tags` | Теги, встречающиеся более одного раза |
| `rule_count`, `rules` | Для каждого правила: часть, индекс, `type`, ссылки `inboundTag` и их разрешимость, назначение `outbound`/`balancer`/`both`/`none` с тегом и разрешимостью, наличие `ruleTag` и число значений каждого поля условия |
| `balancers` | Часть, тег, `selector`, число outbound с таким префиксом, `fallbackTag` и его разрешимость, тип `strategy` |
| `observatory_subjects` | Селекторы `subjectSelector` разделов `observatory` и `burstObservatory` и число совпавших outbound |
| `unsupported_paths` | Места частей, структура которых не поддержана сводкой: например `inbounds[1]` или `routing.rules[4].inboundTag` |

Ссылка `inboundTag` считается разрешённой, если тег есть среди inbound или равен `dns.tag`. Селекторы балансировщиков и наблюдателя сопоставляются по префиксу тега outbound, как в Xray. Правило с `outboundTag` и `balancerTag` одновременно или без обоих отмечается как `both`/`none` с неразрешённым назначением; сводка не выбирает одно из них. Объединение разделов между частями не моделируется, установленный Xray для проверки не вызывается.

В сводку входят только теги, протоколы, имена полей и счётчики. Значения `settings` и `streamSettings`, домены, адреса, порты, пути, пароли, UUID, ключи REALITY и теги правил `ruleTag` в неё не попадают; `repr()` набора показывает только число частей. Структура, не соответствующая ожидаемой (раздел не список, элемент не объект, поле другого типа), отмечается в `unsupported_paths`, а не исправляется и не прерывает чтение.

| Код `XrayConfigErrorCode` | Причина |
|---|---|
| `invalid_xray_parts` | Части не кортеж документов либо имена повторяются; то же для не-словаря в `xray_config_from_files` |
| `invalid_xray_config` | Набор другого типа или повреждён после создания |

`validate_xray_config_set(config)` проверяет набор и каждую часть по её байтам; ошибка документа проходит наружу своим кодом.

## Настройки XKeen

`XKeenSettings(document)` хранит `xkeen.json` целиком. `settings_keys` возвращает имена полей объекта `xkeen`, `killswitch` — флаг `XKeenFlag`:

| `status` (`XKeenFlagStatus`) | Основание |
|---|---|
| `present` | Строка `"on"` или `"off"`; значение в `value` |
| `missing` | Нет объекта `xkeen` или поля `killswitch` |
| `unsupported` | Объект `xkeen` или поле другого типа |
| `unexpected` | Строка с другим значением |

XKeen считает включённым только строковое `"on"`; модель не подменяет другие значения выключенным состоянием, а показывает их статус. `keenvpn.adapters.xkeen_files.xkeen_settings_from_bytes(content)` создаёт модель из байтов файла под именем `xkeen.json`.

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
| `invalid_xkeen_settings` | Настройки не `ConfigDocument`/`XKeenSettings` или повреждены |
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

Источники вызываются по одному разу в фиксированном порядке: части Xray, настройки, init, список исключённых портов, список перехватываемых портов, список исключённых адресов. После отказа или некорректного ответа следующие источники не читаются; частичного результата нет.

```python
from keenvpn.application.proxy_config import InspectProxyConfig, InspectProxyConfigHandler
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
assert result.data.xkeen.settings.killswitch.value == "on"
assert result.data.xkeen.port_53.port_exclude_entry is True
assert "vpn.example.test" not in str(result.data.to_dict())
```

При успехе `data` — `ProxyConfigView` с двумя частями:

| Поле | Содержимое |
|---|---|
| `xray` | `XrayConfigView`: те же поля, что в сводке набора частей; `rules[].conditions` — кортеж `XrayConditionView(key, value_count)`, `sections` — кортеж `XraySectionView(name, parts)` |
| `xkeen.settings` | `XKeenSettingsView`: имя, размер, SHA-256, разделы, `has_xkeen_section`, `settings_keys`, `killswitch` |
| `xkeen.init` | `XKeenInitView`: счётчики, `duplicate_names`, `flags` — кортеж `XKeenInitFlagView(name, status, value, indented_count)` |
| `xkeen.port_exclude`, `xkeen.port_proxying`, `xkeen.ip_exclude` | `XKeenListView` со счётчиками строк и элементов |
| `xkeen.port_53` | `Port53View`: порт, четыре признака записей и флаги `proxy_dns`, `proxy_router` |

Имена файлов, теги, протоколы и имена разделов — технические идентификаторы установки. Домены, адреса, порты слушателей, пути, пароли, теги правил, значения параметров init и записи списков в представление не входят; модели источников недостижимы из результата. `to_dict()` возвращает JSON-совместимый словарь (`sections`, `conditions` и `flags` — словари по именам), представление одного результата не читает источники повторно.

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

## Ошибки домена

`ConfigDocumentError`, `XrayConfigError` и `XKeenConfigError` содержат машинный `code` и фиксированный текст без имён файлов, содержимого и значений. Активное чужое исключение не сохраняется в `__context__` и `__cause__`.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_config_document.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xray_config.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xkeen_config.py -v
python3 -I -S -B -m unittest discover -s tests -p test_xkeen_files.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_proxy_config.py -v
```

Тесты используют искусственные части, синтетический текст init и [обезличенный снимок](../tests/fixtures/router_snapshot/README.md), из которого `tests/support/snapshot.py` собирает модели и управляемые источники; SHA-256 частей Xray совпадают с `manifest.json` снимка. Проверяются строгий JSON с комментариями и без, ссылки между тегами, неподдержанные структуры, повторы и неподдержанный синтаксис init, разбор списков, факты по порту 53, отказ каждого источника, отсутствие секретов в результатах и отсутствие терминала, файлов, сети и процессов во время сценария. Роутер и сеть не требуются.
