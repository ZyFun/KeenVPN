# Импорт правил маршрутизации

Модуль `keenvpn.domain.routing_import` переводит действующие правила Xray в [модель маршрутизации](routing-model.md): группы условий в порядке файла и политику с явным финальным действием. Сценарий `ImportRoutingScheme` выполняет этот перевод поверх [чтения конфигурации Xray и XKeen](proxy-config.md). Код работает в памяти: он не обращается к роутеру, не запускает Xray, не вызывает команды XKeen, не записывает файлы и не сохраняет метаданные. Байты частей, их хеши и неизвестные поля не меняются: исходный `ConfigDocument` остаётся их хранилищем. Успех описывает перевод снимка файлов, а не работу VPN, перехват трафика или маршрут клиента.

Правила разбора повторяют декодер Xray v26.3.27 (`parseFieldRule`, `parseDomainRule`, `ToCidrList`, `Config.Override`): это сверка с исходниками тега, а не с установленным бинарником. Где модель строже декодера, значение не угадывается, а сохраняется в исходном виде с машинной причиной.

## Действующий раздел `routing`

`import_routing_scheme(config)` принимает `XrayConfigSet` и экспортирует каждую часть один раз. При загрузке нескольких файлов Xray берёт раздел `routing` **последней** части, в которой он есть и не равен `null`; прежние разделы не объединяются. `RoutingScheme.routing_part` называет действующую часть, `routing_parts` — все части с разделом в порядке набора. Раздел `outbounds` собирается так же, как `Override`: первая часть берётся целиком, из каждой следующей outbound с уже известным тегом заменяет прежний на месте, новые добавляются в начало списка, а для части со словом `tail` в имени — в конец. Порядок outbound модели не важен: она требует явного финального правила и не использует неявный первый outbound Xray. Объединение выполняется за линейное время по числу outbound: поиск тега идёт по индексу, а не по накопленному списку.

Причины уровня схемы (`ImportReason`):

| Причина | Условие |
|---|---|
| `routing_missing` | Ни одна часть не содержит раздел `routing` |
| `routing_unsupported` | Действующий раздел не объект |
| `rules_unsupported` | `routing.rules` не список; `null` и отсутствие поля означают пустой список |
| `balancers_unsupported` | `routing.balancers` не список либо содержит элемент не объект или без непустого строкового `tag` |
| `outbounds_unsupported` | Раздел `outbounds` части не список либо содержит элемент не объект |
| `field_case_variant` | Ключ верхнего уровня части, раздела `routing`, outbound, балансировщика или его `strategy.type`/`strategy.settings` отличается от поля Xray только регистром; политика не собирается |
| `final_rule_missing` | Последнее правило не является правилом для остатка трафика в поддержанной форме |
| `final_rule_unresolved` | Последнее правило подходит под финальное, но его действие не определено |
| `rule_action_unresolved` | Действие хотя бы одного правила не определено, политика не собрана |

## Группы правил

Каждый элемент `routing.rules` становится `ImportedRuleGroup` с частью, индексом правила, условиями, назначением, именами полей и причинами. Поле `type` декодер v26.3.27 не читает и импорт не проверяет; `ruleTag` учитывается только признаком `has_rule_tag`. Поля условий — все остальные ключи правила.

JSON-декодер Go, которым Xray читает конфигурацию, принимает ключ, отличающийся от имени поля только регистром, а при нескольких вариантах применяет последний. Импорт сопоставляет ключи точно и такие варианты не выбирает: на уровне части, раздела `routing`, outbound и балансировщика вариант даёт причину схемы `field_case_variant` и политика не собирается; вариант `outboundTag` или `balancerTag` оставляет назначение правила без действия; вариант поля условия, например `Domain`, становится неизвестным полем с причиной группы `field_case_variant`. Сравнение выполняется по `casefold`, что шире складывания Go: лишнее совпадение только переводит объект в режим просмотра.

| Вид группы (`RuleGroupKind`) | Условия | Когда |
|---|---|---|
| `rules` | По одному условию на каждое значение `domain`, `domains` и `ip` в порядке файла | Правило содержит только эти поля |
| `rules` | Одно `UnsupportedRuleCondition` с именами полей и каноническим JSON-снимком их значений | Любая причина уровня группы ниже |
| `final` | Нет | Последнее правило только с полем `network` из `tcp` и `udp` в любом регистре и форме `StringList` |

Значения одного правила остаются одной группой: они не дробятся на отдельные правила других групп, не сливаются с соседними и не переупорядочиваются. `domain` и `domains` действуют оба и идут в порядке файла. Оба поля — `StringList`: массив строк либо строка с разделением по запятым без удаления пробелов; элемент массива повторно не делится.

Причины уровня группы:

| Причина | Условие |
|---|---|
| `unsupported_conditions` | Поля условий Xray вне модели: `port`, `network`, `sourceIP`, `source`, `sourcePort`, `user`, `vlessRoute`, `inboundTag`, `protocol`, `attrs`, `localIP`, `localPort`, `process`, `webhook` |
| `unknown_fields` | Поля, которые декодер v26.3.27 не читает под таким именем |
| `conditions_combined` | Домены и адреса в одном правиле: логическое И модель не представляет |
| `values_invalid` | Список не массив строк и не строка, либо `null`; Xray считает `null` отсутствием поля, импорт не угадывает |
| `values_empty` | Пустой список или пустое значение: Xray считает такое условие отсутствующим либо совпадающим со всем |
| `rule_without_conditions` | Правило без полей условий, только с назначением: `BuildCondition` Xray v26.3.27 отклоняет его (`this rule has no effective fields`), и маршрутизатор не запускается; финальным такое правило не считается ни в какой позиции |
| `catch_all_not_last` | Правило только с `network` из `tcp` и `udp` стоит не последним; следующие за ним недостижимы |
| `rule_not_object` | Элемент `routing.rules` не объект; снимок — его JSON |
| `field_case_variant` | Неизвестное поле правила совпадает с полем Xray без учёта регистра |

Группа с любой из этих причин, с неопределённым действием или с неизвестным значением доступна только для просмотра (`read_only`). Импортированные правила не помечаются служебными, не отключаются и не получают [название и идентификатор](routing-model.md#название-и-идентификатор-правила): признаки `protected` и `enabled`, `rule_id` и `name` остаются за доверенным кодом и метаданными менеджера.

## Значения списков

Значение переводится по порядку проверок декодера. Ссылки на наборы геобаз разбираются общим [`parse_geo_reference`](installation.md#ссылки-на-наборы-из-конфигурации-xray); база условия получает ссылку на имя файла (`geoip.dat`, `geosite.dat` или внешний файл) с неизвестными источником, версией и хешем — их даёт инвентарь геобаз по имени файла.

| Значение | Результат | Причина |
|---|---|---|
| `domain:имя` | `DomainCondition(имя)` с поддоменами | — |
| `full:имя` | `DomainCondition(имя, EXACT)` | — |
| `geosite:код` | `GeoSiteCondition(GeoDatabase(GEOSITE, "geosite.dat"), код)` | — |
| `ext:файл:код`, `ext-domain:файл:код` | `GeoSiteCondition` с базой по имени файла | — |
| `geosite:код@атрибут` | `UnknownCondition` | `geosite_attributes` |
| `regexp:`, `keyword:`, `dotless:` | `UnknownCondition` | `domain_regexp`, `domain_keyword`, `domain_dotless` |
| Домен без префикса | `UnknownCondition`: в Xray это подстрочное совпадение | `domain_plain` |
| `domain:` или `full:` с именем, которое модель отклоняет | `UnknownCondition` | `domain_unsupported` |
| `domain:` или `full:` с именем, чья каноническая форма отличается от текста: верхний регистр, конечная точка, Unicode | `UnknownCondition`: Xray сравнивал бы текст как есть | `domain_not_canonical` |
| IPv4/IPv6 или CIDR без битов хоста | `IPCondition` в стандартной форме | — |
| `geoip:код` | `GeoIPCondition(GeoDatabase(GEOIP, "geoip.dat"), код)` | — |
| `ext:файл:код`, `ext-ip:файл:код` | `GeoIPCondition` с базой по имени файла | — |
| `geoip:!код`, `ext:файл:!код` | `UnknownCondition` | `geoip_negated` |
| IPv4-mapped IPv6 `::ffff:a.b.c.d` и сети с адресом в `::ffff:0:0/96`: Xray сводит их к IPv4 с маской IPv4 | `UnknownCondition` | `ip_ipv4_mapped` |
| Адрес с битами хоста, маска с ведущим нулём, зона `%`, имя вместо адреса | `UnknownCondition` | `ip_unsupported` |
| Ссылка, которую загрузчик Xray отклонил бы, либо файл, который модель не принимает | `UnknownCondition` | `geo_reference_unsupported` |
| Код набора вне формы имени набора | `UnknownCondition` | `set_name_unsupported` |

Префиксы сравниваются с учётом регистра, как в Xray: `GEOSITE:cn` — домен без префикса. Каждое неизвестное значение сохраняет исходный текст посимвольно; `ImportedRuleGroup.value_reasons` перечисляет путь значения (`routing.rules[4].domain[3]`) и причину.

## Назначение и действие

`RuleTarget` описывает назначение правила: вид (`outbound`, `balancer`, `both`, `none`), тег, outbound, по которым определено действие, `fallback_tag`, тип `strategy`, действие и причины. Действие берётся только из протокола outbound; `outboundTag` имеет приоритет над `balancerTag`, как в декодере, но правило с обоими непустыми тегами остаётся без действия.

| Протокол outbound | Действие |
|---|---|
| `freedom`, `direct` | `DIRECT` |
| `blackhole`, `block` | `BLOCK` |
| `trojan`, `vless`, `vmess`, `shadowsocks`, `socks`, `http`, `wireguard` | `VPN` — направление без выбора профиля |
| Другой, отсутствующий или не строка | не определено, `outbound_protocol_unsupported` |

Протокол определяет выход, только если outbound не передаёт соединение другому. Непустой `proxySettings.tag` или `streamSettings.sockopt.dialerProxy` задают цепочку: Xray отправляет соединение через указанный outbound, поэтому действие не определяется и назначение получает причину `outbound_chained`. Так же трактуются неподдержанная структура этих разделов и варианты регистра их ключей. Обычные параметры `sockopt` без `dialerProxy` цепочкой не считаются.

Для балансировщика выбираются outbound, тег которых начинается с одного из селекторов (пустой селектор выбирает все); действие определено, когда все выбранные outbound и заданный fallback дают одно действие. Если fallback ведёт в другое направление, его outbound отсутствует, повторяется, имеет неизвестный протокол или передаёт соединение другому, действие не определяется: группа сохраняется только для просмотра, а упрощённая политика не собирается. Так, VPN с резервом BLOCK или DIRECT не представляется безусловным VPN. `fallback_tag` и `strategy` сохраняются как есть: группа резервирования не сводится к одному профилю. Пустой или `null` тег означает отсутствие.

| Причина назначения | Условие |
|---|---|
| `target_missing` | Нет непустого `outboundTag` и `balancerTag` |
| `target_ambiguous` | Заданы оба тега |
| `target_invalid` | Тег не строка и не `null` |
| `field_case_variant` | В правиле есть вариант регистра `outboundTag` или `balancerTag`, в балансировщике — вариант его поля либо вложенного `strategy.type`/`strategy.settings` |
| `target_unresolved` | Тега нет среди действующих outbound или балансировщиков |
| `target_duplicate` | Тег outbound или балансировщика определён более одного раза; ничего не выбирается по первому |
| `outbound_chained` | Outbound назначения, выбранный балансировщиком outbound или fallback передаёт соединение другому |
| `balancer_invalid` | Селектор не `StringList`, `fallbackTag` не строка или `strategy` не объект |
| `balancer_empty` | Селектор не выбрал ни одного outbound, в том числе отсутствующий селектор |
| `balancer_mixed` | Выбранные outbound дают разные действия |
| `fallback_unresolved` | `fallbackTag` не соответствует outbound; действие не определяется |
| `fallback_mixed` | Fallback даёт другое действие, чем выбранные селектором outbound |

Вложенные поля `strategy.type` и `strategy.settings` проверяются на варианты регистра до определения действия. Например, `Type`, `Settings` или одновременные `type` и `Type` дают `field_case_variant`: исходные значения сохраняются без нормализации, действие и тип стратегии не угадываются, группа доступна только для просмотра, а политика не собирается. Это относится и к балансировщикам, на которые правила не ссылаются. Поля, не совпадающие с известными именами даже без учёта регистра, вариантом регистра не считаются.

## Политика

`RoutingScheme.policy` — `RoutingPolicy` из правил всех групп в их порядке и `FinalRoutingRule` с действием финальной группы. Она собирается только когда последнее правило распознано как финальное, его действие определено и действие каждого остального правила определено; иначе `policy` равна `None`, а причина указана в `reasons`. Группы и их условия сохраняются в любом случае. Политика с неизвестным значением или неподдержанным правилом доступна только для просмотра по правилам модели: выбор и [объяснение маршрута](routing-explanation.md) останавливаются на таком правиле, а не подменяют его.

```python
import json

from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.routing import DomainCondition, GeoIPCondition, RoutingAction, UnsupportedRuleCondition
from keenvpn.domain.routing_import import ImportReason, import_routing_scheme
from keenvpn.domain.xray_config import XrayConfigSet


def part(name, document):
    return ConfigDocument(name, json.dumps(document).encode("utf-8"))


# Искусственные части; реальные файлы читает адаптер роутера.
config = XrayConfigSet((
    part("04_outbounds.json", {"outbounds": [
        {"tag": "proxy-out", "protocol": "trojan"}, {"tag": "direct", "protocol": "freedom"},
        {"tag": "blocked", "protocol": "blackhole"},
    ]}),
    part("05_routing.json", {"routing": {
        "rules": [
            {"type": "field", "inboundTag": ["dns-in"], "outboundTag": "direct"},
            {"type": "field", "domain": ["domain:example.test", "full:static.example.test"], "outboundTag": "direct"},
            {"type": "field", "ip": ["geoip:ru", "192.0.2.0/24"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "balancerTag": "vpn-group"},
        ],
        "balancers": [{"tag": "vpn-group", "selector": ["proxy-"], "fallbackTag": "blocked"}],
    }}),
))
scheme = import_routing_scheme(config)
first, domains, addresses, final = scheme.groups

assert isinstance(first.conditions[0], UnsupportedRuleCondition) and first.read_only
assert first.reasons == (ImportReason.UNSUPPORTED_CONDITIONS,) and first.action is RoutingAction.DIRECT
assert domains.conditions[0] == DomainCondition("example.test") and not domains.read_only
assert isinstance(addresses.conditions[0], GeoIPCondition)
assert final.kind.value == "final" and final.target.fallback_tag == "blocked"
assert final.target.reasons == (ImportReason.FALLBACK_MIXED,) and final.read_only
assert scheme.final_action is None and scheme.policy is None and scheme.read_only
assert "example.test" not in json.dumps(scheme.to_diagnostic())
```

`validate_routing_scheme(scheme)` проверяет готовую модель заново: каждое условие и назначение пересобираются своими конструкторами, правила и финальное правило входной политики тоже пересобираются из собственных полей, включая `rule_id` и `name`, и только затем политика сравнивается с собранной из групп. Поэтому строка вместо `RoutingAction`, число вместо `bool` и повреждённое название отклоняются, хотя при сравнении через `==` они равны исходным значениям; политика схемы с присвоенными идентификаторами или названиями тоже расходится с группами и отклоняется. Повреждённое условие или поле группы отклоняется кодом `invalid_rule_group`, назначение — `invalid_rule_target`, расхождение политики, частей или причин — `invalid_routing_scheme`; вход другого типа в `import_routing_scheme` — `invalid_routing_import_config`. `RoutingImportError` содержит машинный `code` и фиксированный текст без значений; активное чужое исключение не сохраняется в `__context__`.

## Безопасный вывод

`to_diagnostic()` схемы содержит действующую часть и части с разделом, число групп и правил, финальное действие, `read_only`, причины, сводку политики и группы. Группа показывает часть, индекс, вид, число условий и их типы, число значений, имена известных полей Xray, неподдержанные поля, число неизвестных полей (`unknown_field_count`), признак `ruleTag`, действие, `read_only`, причины, пути неизвестных значений с причинами и назначение. Домены, адреса, коды наборов, значения неподдержанных полей, имена неизвестных полей, теги правил `ruleTag` и снимки правил в вывод не входят; `repr` моделей скрывает условия и теги.

Теги outbound и балансировщиков задаёт пользователь, поэтому назначение выводит их только после проверки формата. `safe_identifier(value)` пропускает технический идентификатор до 128 символов из букв ASCII, цифр, `_`, `+` и `-`, начинающийся с буквы или цифры; значение с `.`, `/`, `:`, `@`, пробелами, не-ASCII или управляющими символами, а также всё, что разбирается как IP-адрес, заменяется на `None`. Поэтому IPv4- и IPv6-адреса и имена, похожие на домен, в вывод не попадают. Проверка формата не отличает секрет из букв, цифр, `_`, `+` и `-` от обычного тега: такой тег выводится так же, как в [сводке конфигурации прокси](proxy-config.md#конфигурация-xray), поэтому секреты в тегах outbound и балансировщиков хранить не следует. `safe_strategy(value)` пропускает только известные стратегии Xray (`random`, `leastPing`, `roundRobin`, `leastLoad` без учёта регистра). Признаки `tag_known` и `fallback_known` показывают, было ли значение задано; `strategy_known` показывает, удалось ли прочитать строковый `strategy.type` без вариантов регистра вложенных полей. При `field_case_variant` тип стратегии не определяется, даже если исходный объект содержит его. В `outbound_tags` скрытый тег заменяется на `None` на своей позиции. Исходные значения остаются доверенному коду в полях `RuleTarget` и `ImportedRuleGroup.unknown_fields`.

`RoutingScheme.read_only` истинно, если политика не собрана, есть причина уровня схемы либо группа только для просмотра.

## Прикладной сценарий

`ImportRoutingScheme()` не имеет параметров, кроме версии контракта. `ImportRoutingSchemeHandler(proxy)` принимает обработчик `InspectProxyConfigHandler` и читает источники его методом `read()` в том же порядке и с теми же кодами отказов; метод `read()` самого обработчика импорта возвращает `RoutingScheme` для доверенного кода либо `ErrorDetail`.

```python
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingScheme, ImportRoutingSchemeHandler
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
            ConfigDocument("05_routing.json", b'{"routing": {"rules": [{"type": "field", "domain": ["domain:example.test"], '
                           b'"outboundTag": "direct"}, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-out"}]}}'),
        ))

    def current_xkeen_settings(self):
        return XKeenSettings(ConfigDocument("xkeen.json", b'{"xkeen": {"killswitch": "on"}}'))

    def current_xkeen_init(self):
        return parse_xkeen_init(b'start_auto="on"\nproxy_dns="off"\nproxy_router="off"\nipv6_support="on"\n')

    def current_xkeen_list(self, name):
        return XKeenList(name, b"53\n" if name is XKeenListName.PORT_EXCLUDE else b"")


sources = FixedSources()
proxy = InspectProxyConfigHandler(sources, sources, sources, sources)
result = ImportRoutingSchemeHandler(proxy).execute(ImportRoutingScheme())
assert result.succeeded
assert result.data.routing_part == "05_routing.json"
assert [group.kind for group in result.data.groups] == ["rules", "final"]
assert result.data.groups[0].condition_types[0].name == "DomainCondition"
assert result.data.final_action == "VPN" and result.data.read_only is False
assert "example.test" not in str(result.data.to_dict())
```

При успехе `data` — `RoutingSchemeView`:

| Поле | Содержимое |
|---|---|
| `routing_part`, `routing_parts` | Действующая часть и все части с разделом `routing` |
| `group_count`, `rule_count`, `final_action`, `read_only`, `reasons` | Число групп, число правил модели в группах с определённым действием, финальное действие, режим только для просмотра и причины уровня схемы |
| `policy` | `RoutingPolicyView` со счётчиками правил, финальным действием и `read_only` либо `None` |
| `groups` | Кортеж `RuleGroupView`: часть, индекс, вид, `condition_count`, `condition_types` (кортеж `ConditionTypeView(name, count)`), `value_count`, известные поля, неподдержанные поля, `unknown_field_count`, `has_rule_tag`, действие, `read_only`, причины, `value_reasons` (кортеж `ValueReasonView(path, reason)`) и `target` (`RuleTargetView`: вид, `tag_known`, `tag`, `outbound_tags`, `fallback_known`, `fallback_tag`, `strategy_known`, `strategy`, действие и причины в безопасной форме) |

`to_dict()` возвращает JSON-совместимый словарь (`condition_types` — словарь по именам); представление одного результата не читает источники повторно, модели источников недостижимы из результата.

| Ситуация | Категория и код |
|---|---|
| Неверный тип команды | `invalid_request` / `invalid_command` |
| Неверная версия команды | `invalid_request` / `unsupported_contract_version` |
| Отказ или некорректный ответ источника Xray или XKeen | коды сценария `inspect_proxy_config` без изменения; следующие источники не читаются |
| Прочитанные части не удалось перевести | `invalid_source_data` / `routing_import_failed`; доменная причина в `reason` |

`KeyboardInterrupt` и `SystemExit` проходят наружу. Успех означает только перевод прочитанных частей в модель: он не подтверждает принятие конфигурации Xray, работу XKeen, kill-switch или VPN, не создаёт метаданные менеджера и не меняет роутер.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_routing_import.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_routing_import.py -v
python3 -I -S -B -m unittest discover -s tests -p test_import_zero_diff.py -v
```

Тесты используют [обезличенный снимок](../tests/fixtures/router_snapshot/README.md) и искусственные части. Проверяются порядок и состав групп снимка, неизменность байтов частей, перевод каждого вида значения, строковая форма `StringList`, причины уровня группы и назначения, замена `routing` и outbound между частями со сверкой с прямой реализацией `Override`, линейная стоимость объединения outbound по числу выполненных строк, формы финального правила, повторная валидация после подмены полей, линейная стоимость сопоставления, отсутствие секретов в результатах и отсутствие терминала, файлов, сети и процессов во время импорта. Роутер и сеть не требуются.

`test_import_zero_diff.py` выполняет импорт правил вместе с чтением установки и первичным импортом размещения и проверяет, что повторные запуски дают то же представление и не меняют байты частей Xray; подробности — в [локальной проверке чтения установки](installation.md#локальная-проверка).
