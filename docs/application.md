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

## Граница с интерфейсом

Вызывающий код собирает адаптеры, получает ввод, создаёт команду и передаёт её
в `execute()`. Он же выбирает оформление результата: текст, таблицу или JSON.
Сценарий не получает терминальные потоки, функции ввода, подтверждения или
форматирования. Конкретные парсеры и источники передаются через
`application.ports`; application импортирует доменные модели и собственные
контракты, domain не зависит от application, адаптеров или интерфейса.

`ConnectionLinkView`, `RouteExplanationView` и `ErrorDetail` содержат безопасные
данные и пояснения. Заранее заданное сообщение ошибки и преобразование
`to_dict()` относятся к контракту результата: они не добавляют ANSI-оформление,
заголовки меню или выравнивание для терминала. Отображение и сериализация одного
результата не требуют повторного выполнения сценария или чтения его источников.
Примеры с `getpass()` и `print()` ниже показывают именно вызывающий код.

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

## Тестовые адаптеры в памяти

Модуль [`tests/support/in_memory.py`](../tests/support/in_memory.py) содержит
управляемые реализации трёх используемых портов. Это средства тестов:
application получает их через конструкторы обработчиков и не импортирует
`tests`. Адаптеры не используют файлы, сеть, SSH или процессы.

| Адаптер | Настройка и наблюдение |
| --- | --- |
| `InMemoryRoutingPolicySource` | `outcome` — ответ источника правил, `calls` — число обращений |
| `InMemoryConnectionLinkParser` | `outcome` — ответ парсера, `calls` — число обращений; ссылка не сохраняется в полях адаптера и в его кадре |
| `InMemoryGeoDataSource` | `set_response(condition, values, outcome)` — ответ точного запроса; `calls` — неизменяемый снимок истории `GeoDataCall` |

Ответы повторяются до явной замены. `outcome` возвращается как есть, а экземпляр
`BaseException` вызывается как отказ, включая `KeyboardInterrupt`/`SystemExit`.
Для проверки защиты application можно намеренно вернуть неправильный тип,
например `None`.

Ошибка подготовки теста — `AdapterSetupError` — наследует `BaseException`.
Поэтому сценарий не превращает её в `source_failed`, и тест прерывается:

- незаданный ответ вызывает `UnconfiguredResponseError`;
- класс исключения вместо экземпляра, например `OSError` без скобок, вызывает
  `AdapterSetupError`.

Так тест настроенного отказа не может пройти без самого отказа. Незаданный ответ
не заменяется `NO_MATCH`, `UNKNOWN` или прямым маршрутом: эти состояния задаются
явно через `GeoMatch`.

Ключ геоответа включает тип условия, все метаданные базы, имя набора и полный
tuple значений с учётом порядка. `set_response` приводит значения к той же форме,
что и `RoutingContext`: домен — к нижнему регистру и IDNA без завершающей точки,
IP — к стандартной записи. Значения, которые не являются tuple строк,
отклоняются `TypeError`, некорректные домен или IP — `RoutingValidationError`.
Адаптер не читает геобазы и не вычисляет членство в наборе.

Настроенное исключение — один и тот же объект. Перед каждым вызовом адаптер
сбрасывает его traceback и `__context__`, поэтому кадры прошлых вызовов
не накапливаются. После отказа исключение удерживает кадры последнего вызова,
включая команду обработчика, до следующего вызова или замены ответа: присваивания
`outcome` или `set_response` для того же запроса. Замена сбрасывает traceback
и `__context__` прежнего исключения, даже если тест хранит его в переменной.
Не выводите его traceback с локальными переменными.

Пример тестового модуля `tests/test_<имя>.py`, запускаемого через
`unittest discover -s tests`:

```python
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.domain.routing import GeoDatabase, GeoDatabaseKind, GeoIPCondition, RoutingAction, RoutingRule
from keenvpn.domain.routing_explanation import GeoMatch, IPSource
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from tests.support.in_memory import InMemoryGeoDataSource, InMemoryRoutingPolicySource

database = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip", version="test-v1")
condition = GeoIPCondition(database, "test-set")
policies = InMemoryRoutingPolicySource(RoutingPolicy(
    (RoutingRule(condition, RoutingAction.VPN),), FinalRoutingRule(RoutingAction.DIRECT),
))
geodata = InMemoryGeoDataSource()
addresses = ("192.0.2.10",)
geodata.set_response(condition, addresses, GeoMatch(MatchResult.MATCH, database))
handler = ExplainRouteHandler(policies, geodata)
command = ExplainRoute(ips=addresses, ip_source=IPSource.DESTINATION)
assert handler.execute(command).data.selection.action == "VPN"
assert geodata.calls[0].values == addresses

geodata.set_response(condition, addresses, OSError("Искусственный отказ источника."))
result = handler.execute(command)
assert result.error.code == "rule_matcher_failed"
assert result.data is None
assert policies.calls == 2
```

Пакет импортируется как `tests.support`, поэтому модуль также запускается
напрямую: `python3 -I -S -B tests/test_<имя>.py`.

`GeoDataCall.condition` и `.values` доступны тесту явно. `repr()` истории
показывает только тип условия и число значений, а `repr()` адаптеров скрывает
ответы. Используйте только искусственные данные, в том числе в исключениях.
Прямой доступ к полям или дамп объектов не является безопасным отчётом.
`InMemoryConnectionLinkParser` не проверяет переданную ссылку: тесты синтаксиса
URI должны использовать `TrojanLinkParser`. Успех с настроенными ответами
проверяет сценарий, а не работоспособность VPN.

Общие проверки для тестов сценариев:

- `tests.support.isolation.forbid_external_effects()` на время блока запрещает
  терминал, файлы, сеть и запуск процессов. При выходе, в том числе по исключению
  блока, он сообщает о запрещённом вызове, даже если сценарий перехватил его отказ.
  Проверяются также чтение строк и итерация по stdin, скрытый ввод `getpass`,
  определение размеров терминала, `isatty()` стандартных потоков и `os.isatty`,
  `os.read`/`os.write` и исходные стандартные
  потоки `sys.__stdin__`, `sys.__stdout__`, `sys.__stderr__`. Подмены восстанавливаются
  после выхода из блока. Это контроль перечисленных API, а не системная песочница.
- `tests.support.privacy.reachable()` возвращает объекты, достижимые из результата.
- `tests.support.privacy.frame_locals()` возвращает локальные переменные кадров
  указанного модуля из traceback; отсутствие таких кадров считается ошибкой теста.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p 'test_application*.py' -v
python3 -I -S -B -m unittest discover -s tests -p test_in_memory_adapters.py -v
```

Тесты используют искусственные ссылки, домены и документальные IP-адреса,
управляемые источники с отказами и проверяют отсутствие обращений к терминалу
и приватных значений в результатах. Роутер и сеть не требуются.

`test_application_boundary.py` проверяет направления импортов application,
domain и adapters, включая относительные импорты и алиасы, и запрещает
зависимости от интерфейса, терминальных библиотек, тестовых адаптеров и явную
динамическую загрузку: `__import__`, `exec`, `eval`, `compile`, `importlib`,
`pkgutil` и `runpy`. Проверка исходников выявляет `input`/`print` и
ANSI-последовательности в строках и байтах, а в application и domain — также
прямой ввод-вывод через `open`, `os.read`, `os.write` и `os.open`; адаптерам
чтение файлов разрешено. Она дополнена выполнением обоих сценариев с запрещённым
терминалом и представлением результата вызывающим кодом в JSON и текст из
безопасных данных без повторных обращений к парсеру и источникам. Обычные
сообщения и безопасные словари разрешены. Это проверка явных зависимостей и выполненных ветвей,
а не доказательство отсутствия любых возможных динамических обращений.
