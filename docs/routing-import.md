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

Группа с любой из этих причин, с неопределённым действием или с неизвестным значением доступна только для просмотра (`read_only`). Импортированные правила не помечаются служебными, не отключаются и не получают [название и идентификатор](routing-model.md#название-и-идентификатор-правила): признаки `protected` и `enabled`, `rule_id` и `name` остаются за доверенным кодом и метаданными менеджера; [привязка](#названия-и-идентификаторы-правил) записей метаданных к правилам выполняется отдельно и импорт не меняет.

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

`balancer_fallbacks(config)` возвращает назначение `fallbackTag` каждого балансировщика действующего раздела `routing` в порядке файла, разрешённое так же, как `outboundTag` правила: `RuleTarget` вида `outbound` с действием либо без действия с причиной (`target_unresolved`, `target_duplicate`, `outbound_chained`, `outbound_protocol_unsupported`). Структура балансировщика проверяется до разрешения теми же проверками, что у назначения правила: элемент не объект, тег не непустая строка, селектор не `StringList`, `fallbackTag` не строка или `strategy` не объект дают `balancer_invalid`, варианты регистра полей — `field_case_variant`. Действия селектора и fallback не сравниваются, поэтому группа VPN с резервом BLOCK получает действие своего fallback. `None` в кортеже — `fallbackTag` не задан (отсутствует, пустой или `null`), пустой кортеж — раздела `routing` или балансировщиков нет. Вместо кортежа возвращается `None`, если outbound имеют неподдержанную структуру или варианты регистра полей, раздел `routing` не объект или содержит вариант регистра своих полей, список балансировщиков не массив либо документ части содержит вариант регистра `routing` или `outbounds`. Назначения содержат исходные теги и предназначены доверенному коду; их использует [режим резерва сводки состояния](status-summary.md#режим-резерва).

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

Теги outbound и балансировщиков задаёт пользователь, поэтому назначение выводит их только после проверки формата из общего модуля `keenvpn.domain.xray_identifiers` — того же, что использует [сводка конфигурации прокси](proxy-config.md#безопасный-вывод-сводки). `safe_identifier(value)` пропускает технический идентификатор до 128 символов из букв ASCII, цифр, `_`, `+` и `-`, начинающийся с буквы или цифры; значение с `.`, `/`, `:`, `@`, пробелами, не-ASCII или управляющими символами, а также всё, что разбирается как IP-адрес, заменяется на `None`. Поэтому IPv4- и IPv6-адреса и имена, похожие на домен, в вывод не попадают. Проверка формата не отличает секрет из букв, цифр, `_`, `+` и `-` от обычного тега: такой тег выводится так же, как в сводке, поэтому секреты в тегах outbound и балансировщиков хранить не следует. `safe_strategy(value)` пропускает только известные стратегии Xray (`random`, `leastPing`, `roundRobin`, `leastLoad` без учёта регистра). Список полей условий `XRAY_RULE_CONDITION_FIELDS` и список стратегий тоже определены в общем модуле и доступны из `keenvpn.domain.routing_import` под прежними именами. Признаки `tag_known` и `fallback_known` показывают, было ли значение задано; `strategy_known` показывает, удалось ли прочитать строковый `strategy.type` без вариантов регистра вложенных полей. При `field_case_variant` тип стратегии не определяется, даже если исходный объект содержит его. В `outbound_tags` скрытый тег заменяется на `None` на своей позиции. Исходные значения остаются доверенному коду в полях `RuleTarget` и `ImportedRuleGroup.unknown_fields`.

`RoutingScheme.read_only` истинно, если политика не собрана, есть причина уровня схемы либо группа только для просмотра.

## Прикладной сценарий

`ImportRoutingScheme()` не имеет параметров, кроме версии контракта. `ImportRoutingSchemeHandler(proxy)` принимает обработчик `InspectProxyConfigHandler` и читает источники его методом `read()` в том же порядке и с теми же кодами отказов; метод `read()` самого обработчика импорта возвращает `RoutingScheme` для доверенного кода либо `ErrorDetail`. Метод `import_models(models)` переводит уже прочитанные `ProxyConfigModels` в схему с тем же кодом отказа `routing_import_failed`; `read()` вызывает его после чтения, а [список правил для меню](#список-правил-для-меню) читает модели один раз сам через свойство `proxy` обработчика и использует их и для схемы, и для позиций назначений в структурной сводке.

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

## Названия и идентификаторы правил

Название и стабильный идентификатор правила — [метаданные менеджера](manager-metadata.md#записи-правил), не поля Xray JSON. Импорт их не присваивает; модуль `keenvpn.domain.rule_binding` находит запись раздела `rules` для каждого правила схемы при повторном импорте, а прикладные сценарии `InspectRoutingRules` и `AssignRuleIdentifiers` (`keenvpn.application.routing_rules`) показывают правила с идентичностью и присваивают идентификаторы.

### Семантический ключ и привязка

`rule_key(rule)` строит `RuleKey(condition, value, action)` из правила модели: тип условия, каноническое значение в форме модели и действие. Позиция, группа, `ruleTag`, теги outbound и балансировщиков, идентификатор, название, состояние и защита правила в ключ не входят.

| Условие | `condition` | `value` |
|---|---|---|
| `DomainCondition` | `domain` | режим и имя: `subdomains:example.test`, `exact:static.example.test`; имя уже нормализовано (IDNA, нижний регистр) |
| `IPCondition` | `ip` | адрес или сеть в стандартной записи |
| `GeoIPCondition`, `GeoSiteCondition` | `geoip`, `geosite` | имя файла базы и код набора: `geoip.dat:ru`; версия и хеш базы не входят |
| `UnknownCondition` | `unknown` | семейство и исходный текст: `domain:regexp:^x` |
| `UnsupportedRuleCondition` | `unsupported` | JSON-снимок полей правила с отсортированными ключами объектов на всех уровнях: перестановка полей в файле Xray ключ не меняет, порядок массивов и типы значений сохраняются; та же нормализация применяется к значению записи при сопоставлении; значение записи, которое не является строгим JSON (повтор ключа, `NaN`, `Infinity`) или не кодируется обратно, сопоставляется как есть и правила не находит |

`bind_routing_scheme(scheme, records)` берёт правила всех групп схемы в порядке файла (`scheme_rules`): группа без определённого действия правил не даёт; при наличии политики это ровно её правила, а без политики, например при неоднозначном резерве балансировщика, правила групп остаются. Привязка линейна по числу правил и записей и ничего не выбирает по первому: правило и запись сопоставляются только когда их ключ единственный с обеих сторон. Поэтому привязка переживает перемещение, вставку и удаление соседних правил и перенос значения между группами с тем же действием, а ручная правка значения или действия вне менеджера отвязывает только это правило. Запись, не нашедшая правила, сохраняется в метаданных и считается отдельно; удаляет её только явное действие, которого в этой версии нет.

| Причина (`BindingReason`) | У правила | У записи |
|---|---|---|
| `rule_duplicate` | ключ встречается среди правил больше одного раза; все такие правила без привязки, даже если запись есть | запись с таким ключом не привязана |
| `record_duplicate` | ключ встречается среди записей больше одного раза; правило без привязки | обе записи не привязаны и сохраняются |
| `record_missing` | записи с ключом правила нет: идентификатор ещё не присвоен | — |
| `rule_missing` | — | правила с ключом записи нет: удалено или изменено вне менеджера |

Результат `RuleBinding` содержит `rules` — кортеж `BoundRule(index, rule, record, reason)`, где привязанное правило несёт `rule_id` и `name` записи; `unbound_records` — записи без правила с причиной; `policy` — `RoutingPolicy` с идентичностью, если у схемы есть политика. `bind_rule_records(rules, records, policy)` делает то же для произвольного списка правил без идентичности. Повреждённый вход — `RuleBindingError` с кодами `invalid_binding_rules`, `invalid_binding_records`, `invalid_binding_scheme`, `invalid_rule_binding` без значений и чужой цепочки исключений. `to_diagnostic()` привязки показывает счётчики, по каждому правилу позицию, итог (`bound` либо причина) и диагностику правила, по каждой записи без правила — идентификатор, признак и длину названия и причину; названия и значения ключей не выводятся.

### Прикладные сценарии

`InspectRoutingRulesHandler(routing, store)` принимает обработчик `ImportRoutingSchemeHandler` и порт `ManagerMetadataStore`, читает схему его методом `read()` с тем же порядком и кодами отказов, один раз читает метаданные и ничего не записывает; `AssignRuleIdentifiersHandler(routing, store, rule_ids=new_rule_id)` после того же чтения присваивает идентификаторы правилам с причиной `record_missing` и пишет раздел `rules` один раз только при изменениях.

```python
import os
import tempfile

from keenvpn.adapters.manager_metadata_files import ManagerMetadataFiles
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingSchemeHandler
from keenvpn.application.routing_rules import (
    AssignRuleIdentifiers, AssignRuleIdentifiersHandler, InspectRoutingRules, InspectRoutingRulesHandler,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet


class FixedSources:
    """Искусственные данные; реальные файлы читает адаптер роутера."""

    def current_xray_config(self):
        return XrayConfigSet((
            ConfigDocument("04_outbounds.json", b'{"outbounds": [{"tag": "proxy-out", "protocol": "trojan"}, '
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
routing = ImportRoutingSchemeHandler(InspectProxyConfigHandler(sources, sources, sources, sources))
store = ManagerMetadataFiles(os.path.realpath(tempfile.mkdtemp()) + "/keenvpn")

view = InspectRoutingRulesHandler(routing, store).execute(InspectRoutingRules()).data
assert (view.metadata_present, view.rule_count, view.rules[0].binding) == (False, 1, "record_missing")
assert store.read_metadata() is None  # Просмотр не создал файл.

assign = AssignRuleIdentifiersHandler(routing, store)
assert assign.execute(AssignRuleIdentifiers()).data.outcome == "created"
assert assign.execute(AssignRuleIdentifiers()).data.outcome == "unchanged"
view = InspectRoutingRulesHandler(routing, store).execute(InspectRoutingRules()).data
rule = view.rules[0]
assert (rule.binding, rule.has_id, rule.has_name, rule.part, rule.group_index, rule.offset) == ("bound", True, False, "05_routing.json", 0, 0)
assert "example.test" not in str(view.to_dict())
print(rule.rule_id == store.read_metadata().metadata.rules[0].rule_id)
```

`RoutingRulesView`:

| Поле | Содержимое |
|---|---|
| `routing_part`, `metadata_present`, `scheme_read_only`, `policy_present` | Действующая часть, наличие файла метаданных, режим только для просмотра схемы и наличие политики |
| `rule_count`, `bound_rule_count`, `named_rule_count`, `unbound_rule_count` | Число правил схемы, привязанных, с названием и без привязки |
| `record_count`, `unbound_record_count` | Число записей раздела `rules` (`None`, если раздел не записан) и число записей без правила |
| `rules` | Кортеж `RuleIdentityView`: `index` среди правил схемы, `part`, `group_index` правила Xray и `offset` внутри группы, `condition_type`, `action`, `read_only`, `has_id`, `rule_id`, `has_name`, `name_length`, `binding` (`bound` либо причина) |
| `unbound_records` | Кортеж `UnboundRecordView`: `rule_id`, `has_name`, `name_length`, `reason` |

`AssignRuleIdentifiers` возвращает `RuleIdentityAssignmentView(outcome, assigned_count, rules)`: `created` — записи добавлены и раздел записан, `unchanged` — присваивать нечего (без новых записей операция завершается до кодирования, поэтому допустимый компактный файл, чья форматированная копия превысила бы предел размера, повтор не блокирует) или кандидат совпал с файлом по каноническим байтам, записи не было; `rules` — представление после операции. Кандидат — прочитанные метаданные с дополненным разделом: размещение, неизвестные поля, прежние записи, в том числе без правила, сохраняются; новые записи идут после прежних в порядке правил. Ревизию в последний момент сверяет хранилище; ревизия, которую вернула запись, должна совпасть с SHA-256 кандидата. Домены, адреса, коды наборов, названия и ключи в представления не входят; идентификаторы показываются после проверки формата. Коды отказов перечислены в [описании прикладных сценариев](application.md#правила-с-названиями-и-идентификаторами). Просмотр не вызывает запись ни при каких данных, поэтому первое подключение к действующей установке не создаёт раздел `rules` и не пишет метаданные, пока идентификаторы не присвоены явно.

### Список правил для меню

`ListRoutingRules` — третья читающая команда модуля `keenvpn.application.routing_rules`, за которой закреплён пункт меню «Все правила по порядку / поиск». `ListRoutingRulesHandler(routing, store)` принимает обработчик `ImportRoutingSchemeHandler` и порт `ManagerMetadataStore` либо `None`, если хранилище не подключено. Источники Xray и XKeen читаются один раз обработчиком конфигурации прокси в его порядке и с его кодами, схема строится `import_models()`, а позиции назначений групп берутся из структурной сводки тех же моделей. Хранилище читается один раз, когда подключено; запись не вызывается ни при каких данных.

```python
import os
import tempfile

from keenvpn.adapters.manager_metadata_files import ManagerMetadataFiles
from keenvpn.application.proxy_config import InspectProxyConfigHandler
from keenvpn.application.routing_import import ImportRoutingSchemeHandler
from keenvpn.application.routing_rules import (
    AssignRuleIdentifiers, AssignRuleIdentifiersHandler, ListRoutingRules, ListRoutingRulesHandler, MetadataState,
    TargetPositionState,
)
from keenvpn.domain.config_document import ConfigDocument
from keenvpn.domain.xkeen_config import XKeenList, XKeenListName, XKeenSettings, parse_xkeen_init
from keenvpn.domain.xray_config import XrayConfigSet


class FixedSources:
    """Искусственные данные; реальные файлы читает адаптер роутера."""

    def current_xray_config(self):
        return XrayConfigSet((
            ConfigDocument("04_outbounds.json", b'{"outbounds": [{"tag": "proxy-out", "protocol": "trojan"}, '
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
routing = ImportRoutingSchemeHandler(InspectProxyConfigHandler(sources, sources, sources, sources))
store = ManagerMetadataFiles(os.path.realpath(tempfile.mkdtemp()) + "/keenvpn")

view = ListRoutingRulesHandler(routing, None).execute(ListRoutingRules()).data
assert view.metadata_state is MetadataState.NOT_CONNECTED and view.identity is None
assert [group.rule_count for group in view.groups] == [1, 0]  # Финальная группа правил модели не даёт.
assert view.groups[0].target_position_state is TargetPositionState.RESOLVED
assert (view.groups[0].target_position.part, view.groups[0].target_position.index) == ("04_outbounds.json", 1)

view = ListRoutingRulesHandler(routing, store).execute(ListRoutingRules()).data
assert view.metadata_state is MetadataState.ABSENT
assert view.groups[0].rules[0].binding == "record_missing" and store.read_metadata() is None

assert AssignRuleIdentifiersHandler(routing, store).execute(AssignRuleIdentifiers()).data.outcome == "created"
view = ListRoutingRulesHandler(routing, store).execute(ListRoutingRules()).data
rule = view.groups[0].rules[0]
assert (view.metadata_state, view.identity.bound_rule_count, rule.binding, rule.has_name, rule.name) == (MetadataState.PRESENT, 1, "bound", False, None)
assert "example.test" not in str(view.to_dict())
print(rule.rule_id == store.read_metadata().metadata.rules[0].rule_id)
```

`RuleListView`:

| Поле | Содержимое |
|---|---|
| `scheme` | `RoutingSchemeView` схемы импорта: группы в фактическом порядке действующего раздела `routing` |
| `metadata_state` | `MetadataState`: `not_connected` — хранилище не передано, `absent` — файла метаданных нет, `present` — метаданные прочитаны (раздел `rules` может отсутствовать), `failed` — хранилище отказало или ответило не по контракту |
| `metadata_error` | `ErrorDetail` отказа хранилища с тем же кодом, что у сценариев метаданных, и безопасным следующим шагом; только при `failed` |
| `identity` | `RuleIdentitySummaryView(bound_rule_count, named_rule_count, unbound_rule_count, record_count, unbound_record_count)`; только при `absent` и `present`, `record_count` — `None`, если раздел `rules` не записан |
| `groups` | Кортеж `RuleGroupIdentityView` в порядке групп схемы: `index` правила Xray, `rule_count` правил модели, `target_position_state` и `target_position`, `rules` |

Чтение моделей, схемы, сводки и привязки вынесено в `read_scheme_identity(routing, store)` и общее с [объяснением маршрута](application.md#объяснение-маршрута) по импортированной схеме; позицию назначения по правилу сводки даёт `resolve_target_position`.

`target_position_state` (`TargetPositionState`): `resolved` — тег носит ровно один outbound или балансировщик среди всех частей, и `target_position` указывает его; `ambiguous` — тег повторяется, позиция не выбирается по первому; `unresolved` — тега нет ни в одной части; `absent` — у правила нет ни `outboundTag`, ни `balancerTag`; `unsupported` — заданы оба тега; `unavailable` — сводка не описывает правило, например оно не объект. Скрытый как небезопасный тег позицию не теряет. `rules` — кортеж `RuleListEntryView(index, offset, condition_type, action, read_only, has_id, rule_id, has_name, name, binding)` либо `None` при `not_connected` и `failed`: тогда ни одно правило не помечается ни привязанным, ни непривязанным. Название — пользовательский текст, проверенный `valid_rule_name` при построении; идентификатор проходит проверку формата. Домены, адреса, коды наборов и ключи записей в представление не входят. Контракт `InspectRoutingRules` не меняется: его представление по-прежнему несёт только признак и длину названия.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_routing_import.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_routing_import.py -v
python3 -I -S -B -m unittest discover -s tests -p test_rule_binding.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_routing_rules.py -v
python3 -I -S -B -m unittest discover -s tests -p test_import_zero_diff.py -v
```

Тесты используют [обезличенный снимок](../tests/fixtures/router_snapshot/README.md) и искусственные части. Проверяются порядок и состав групп снимка, неизменность байтов частей, перевод каждого вида значения, строковая форма `StringList`, причины уровня группы и назначения, замена `routing` и outbound между частями со сверкой с прямой реализацией `Override`, линейная стоимость объединения outbound по числу выполненных строк, формы финального правила, повторная валидация после подмены полей, линейная стоимость сопоставления, отсутствие секретов в результатах и отсутствие терминала, файлов, сети и процессов во время импорта. Роутер и сеть не требуются.

`test_rule_binding.py` проверяет ключ каждого типа условия, его независимость от идентичности, состояния и метаданных базы, привязку при перемещении, вставке, удалении и перегруппировке правил в искусственных частях Xray, отвязку одного правила после ручной правки, дубли ключей с обеих сторон без выбора по первому, записи без правила, линейную стоимость по числу выполненных строк, отказы на повреждённый вход и отсутствие названий и значений в выводе. `test_application_routing_rules.py` проверяет оба сценария на снимке и хранилище в памяти: просмотр без записи и без создания файла, позиции по группам схемы, привязку записей с названиями, присвоение всем правилам и только недостающим с сохранением прежних записей, повтор без записи, неканонический файл без перезаписи, отказы фабрики и каждого отказа хранилища, неподтверждённую запись, внешнюю правку перед сверкой ревизии, приватность результатов, а с настоящим файловым хранилищем во временном каталоге — что просмотр не создаёт каталог и файл, а повтор присвоения не меняет inode, время изменения и байты.

`test_import_zero_diff.py` выполняет импорт правил вместе с чтением установки и первичным импортом размещения и проверяет, что повторные запуски дают то же представление и не меняют байты частей Xray; подробности — в [локальной проверке чтения установки](installation.md#локальная-проверка).
