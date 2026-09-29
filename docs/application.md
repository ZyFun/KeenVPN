# Прикладные сценарии

Пакет `keenvpn.application` содержит сценарии, которые принимают типизированную
команду и возвращают структурированный результат. Сценарии не печатают,
не читают терминал и не запрашивают подтверждение: отображение результата
и диалог с пользователем остаются на стороне вызывающего кода.

Доступны два сценария только для чтения:

| Команда | Обработчик | Что делает |
| --- | --- | --- |
| `InspectConnectionLink` | `InspectConnectionLinkHandler` | Разбирает ссылку подключения и показывает её формат без значений полей |
| `ExplainRoute` | `ExplainRouteHandler` | Строит [статическое объяснение маршрута](routing-explanation.md) по правилам из источника |

Сценарии работают в памяти. Они не устанавливают соединения, не выполняют DNS,
не запускают Xray, не записывают файлы и не меняют конфигурацию роутера.
Успешный результат не подтверждает работоспособность сервера или VPN.

## Результат

`execute(command)` возвращает `Result` и не вызывает исключений при ожидаемых
отказах. Поля результата:

| Поле | Значение |
| --- | --- |
| `contract_version` | Версия формата команд и результатов, сейчас `1` (`CONTRACT_VERSION`) |
| `operation_id` | Идентификатор вызова; по умолчанию случайная hex-строка |
| `command` | Имя команды: `inspect_connection_link` или `explain_route` |
| `status` | `OperationStatus.SUCCEEDED` или `OperationStatus.FAILED` |
| `data` | Безопасное представление при успехе, иначе `None` |
| `error` | `ErrorDetail` при отказе, иначе `None` |

Успех всегда содержит данные без ошибки, отказ — ошибку без данных; другие
сочетания отклоняются конструктором. `result.succeeded` проверяет статус,
`result.to_dict()` возвращает JSON-совместимый словарь. Результаты и их
представления неизменяемы.

`ErrorDetail` содержит `category`, стабильный английский `code`, необязательное
уточнение `reason` и русский текст `message`. Текст задан заранее и не содержит
входных значений, фрагментов ссылки или сообщений внешних исключений.
Для обработки ошибки используйте `category` и `code`, а не текст.

| `ErrorCategory` | Когда возникает |
| --- | --- |
| `invalid_request` | Команда неверного типа или с полями неверных типов (`invalid_command`), либо другой версии контракта (`unsupported_contract_version`) |
| `invalid_input` | Введённое значение некорректно: ссылка, домен, IP или сочетание источников |
| `unsupported` | Значение корректно по форме, но не поддерживается: схема, режим безопасности, транспорт, параметр |
| `source_failed` | Источник данных не смог выполнить запрос |
| `invalid_source_data` | Источник вернул данные, противоречащие контракту или модели |

`KeyboardInterrupt` и `SystemExit` не перехватываются.

Идентификатор вызова можно задать своей функцией `operation_ids`
в конструкторе обработчика, например для воспроизводимых тестов.

## Проверка ссылки подключения

Ссылка передаётся как `SecretValue` со строкой, поэтому `repr()` команды её
не показывает. Другой тип ссылки или значения внутри — `invalid_request` /
`invalid_command`.
Обработчик получает парсер как параметр; для Trojan используется
`keenvpn.adapters.trojan_uri.TrojanLinkParser`.

```python
from getpass import getpass

from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.connections import InspectConnectionLink, InspectConnectionLinkHandler
from keenvpn.domain.connection import SecretValue

handler = InspectConnectionLinkHandler(TrojanLinkParser())
result = handler.execute(InspectConnectionLink(SecretValue(getpass("Ссылка подключения: "))))
if result.succeeded:
    print(result.data.protocol, result.data.transport)
else:
    print(result.error.category.value, result.error.code, result.error.message)
```

При успехе `data` — `ConnectionLinkView` с полями `protocol`, `security`,
`transport` и признаками наличия `has_sni`, `has_host`, `has_fingerprint`,
`has_name`. Адрес, порт, пароль, путь и прочие значения в результат не входят,
разобранная модель подключения в нём не сохраняется.

Отказ `TrojanLinkParser` передаёт коды [разбора Trojan URI](trojan-uri.md):
`invalid_uri` становится категорией `invalid_input`, `unsupported_uri` —
`unsupported`; `reason` и `message` сохраняются. Схема, отличная от `trojan`,
тоже даёт `unsupported`.

Парсер — любой объект с методом `parse(link) -> TrojanConnection`, который
сообщает об отказе исключением `keenvpn.application.ports.ConnectionLinkRejected`
с видом `LinkRejection.INVALID` или `LinkRejection.UNSUPPORTED`, непустым кодом
и безопасным текстом. Любое другое исключение парсера заменяется ошибкой
`source_failed` / `connection_parser_failed`. Отказ неизвестного вида даёт
`invalid_source_data` / `invalid_parser_rejection`, возврат не модели
подключения — `invalid_source_data` / `invalid_connection_model`.

## Объяснение маршрута

`ExplainRoute` принимает те же именованные предположения, что и
[`RoutingContext`](routing-explanation.md#входные-предположения): `domain`,
`domain_source`, `ips`, `ip_source`. Значения считаются приватными,
`repr()` команды их скрывает.

Тип полей проверяется до разбора значений: `domain` — `str` или `None`,
источники — только `DomainSource` и `IPSource`, `ips` — tuple строк или `None`.
В отличие от `RoutingContext`, list не принимается. Нарушение типа —
`invalid_request` / `invalid_command`; некорректное по смыслу значение
правильного типа — `invalid_input`.

Обработчику передаются источник правил и, при необходимости, источник геоданных:

- `policies` — объект с методом `current_routing_policy() -> RoutingPolicy`;
- `geodata` — объект с методом `match(condition, values) -> GeoMatch`
  с тем же контрактом, что у `geo_matcher` в `explain_route`. Без него
  условия GeoIP/GeoSite дают `unknown`.

```python
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.domain.routing import DomainCondition, RoutingAction, RoutingRule
from keenvpn.domain.routing_explanation import DomainSource
from keenvpn.domain.routing_policy import FinalRoutingRule, RoutingPolicy


class FixedPolicy:
    def current_routing_policy(self):
        return RoutingPolicy(
            (RoutingRule(DomainCondition("example.test"), RoutingAction.VPN),),
            FinalRoutingRule(RoutingAction.DIRECT),
        )


result = ExplainRouteHandler(FixedPolicy()).execute(
    ExplainRoute(domain="example.test", domain_source=DomainSource.DESTINATION)
)
assert result.data.selection.action == "VPN"
```

Сначала проверяются предположения; при ошибке источник правил не вызывается.
При успехе `data` — `RouteExplanationView`: признак `preliminary`, источники
имени и адресов, число адресов `ip_count`, ограничения `assumptions`, шаги
`steps` и выбор `selection`. Каждый шаг содержит позицию, тип условия, признаки
`enabled` и `protected`, действие, результат, машинный `reason_code`
(например `domain`, `disabled`, `geodata_missing`), текст причины и безопасные
признаки базы. Значения доменов, IP, категорий, ссылок и версий баз
в представление не входят.

`selection=None` при успешном статусе означает, что первое неизвестное условие
не позволило выбрать действие. Это не отказ сценария и не выбор BLOCK.

| Ситуация | Категория и код |
| --- | --- |
| Некорректные предположения | `invalid_input`: `invalid_routing_context`, `invalid_domain` или `invalid_ip_or_cidr` |
| Источник правил вызвал исключение | `source_failed` / `routing_policy_unavailable` |
| Источник вернул не `RoutingPolicy` | `invalid_source_data` / `invalid_routing_policy` |
| Источник геоданных вызвал исключение | `source_failed` / `rule_matcher_failed` |
| Неверный ответ источника геоданных или подмена метаданных базы | `invalid_source_data` / `invalid_geodata_result` или `geodata_database_mismatch` |

Текст и цепочка исключений источников в результат не попадают.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_application.py -v
```

Тесты используют искусственные ссылки, домены и документальные IP-адреса,
управляемые источники с отказами и проверяют отсутствие обращений к терминалу
и приватных значений в результатах. Роутер и сеть не требуются.
