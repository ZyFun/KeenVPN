# Реестр протоколов и возможностей

`application.protocol_registry` выбирает доверенный модуль по типу профиля
или схеме URI. `EngineRegistry` отдельно выбирает обработчик движка по
явному ID, протоколу и операции. Выбор не вызывает обработчики, не проверяет
сервер и не устанавливает соединений.

## Состав поставки и граница доверия

`adapters.protocols.bundled_protocols()` явно регистрирует Trojan: модель
`TrojanConnection`, существующий `TrojanLinkParser.parse`, схему `trojan`
и метаданные полей. Возможность `parse_uri` включает существующую проверку
[Trojan URI](trojan-uri.md). Отдельного валидатора произвольно созданной
модели в этой регистрации нет: `validate_parameters` даёт явный отказ.
Реестр не меняет поведение `InspectConnectionLink` и парсера.

Регистрации движков по умолчанию отсутствуют. Запрос операции `xray`
возвращает `unknown_engine`; наличие Xray в системе здесь не исследуется.

Состав реестров задаёт доверенный Python-код сборки из поставки. Пользователь
передаёт только селектор, а не модуль, callback или путь импорта. Реестр не
читает каталог плагинов, entry points и настройки, не скачивает и не
импортирует код по URI. Это граница сборки приложения, а не песочница для
произвольного Python: переданные обработчики уже должны быть доверенными.

## Проверка через application

`InspectProtocolSupport` получает ровно одно из двух: `protocol` со строковым
типом профиля либо `uri` как `SecretValue`. Поле `capability` необязательно;
для проверки операции движка нужны одновременно `engine` и
`engine_capability`.

```python
from keenvpn.adapters.protocols import bundled_protocols
from keenvpn.application.protocol_registry import EngineCapability, ProtocolCapability
from keenvpn.application.protocol_support import InspectProtocolSupport, InspectProtocolSupportHandler

handler = InspectProtocolSupportHandler(bundled_protocols())
result = handler.execute(InspectProtocolSupport(
    protocol="trojan", capability=ProtocolCapability.PARSE_URI,
))
assert result.succeeded
assert result.data.capabilities == ("parse_uri",)
assert result.data.engine is None

unsupported = handler.execute(InspectProtocolSupport(
    protocol="trojan", engine="xray", engine_capability=EngineCapability.PROBE,
))
assert unsupported.error.code == "unknown_engine"
```

Порядок проверки: тип команды → версия контракта → типы и сочетания полей →
выбор протокола → его возможность → движок, сочетание и операция. Ошибка
протокола не вызывает поиск движка. Движок не выбирается автоматически,
неизвестная операция не заменяется другой и не приводит к DIRECT/fallback.

При выборе по URI читается только ASCII-схема перед `://`, без
percent-decoding. Регистр схемы несущественен; идентификатор протокола
сравнивается точно. Пустая или неверная схема отклоняется, корректная
незарегистрированная схема даёт `unknown_uri_scheme`. Тело URI может быть
некорректным: успех этого сценария подтверждает только доступность модуля.
Проверку тела выполняет его парсер отдельным вызовом.

Успешный `ProtocolSupportView` содержит статические `protocol`, `uri_schemes`,
`capabilities`, описания `fields`, а также выбранные `engine` и
`engine_capability` либо `None`. У поля есть только `name`, `secret`,
`required`; значения и defaults не передаются. Все значения полей Trojan
считаются приватными. Объекты модуля, модели, обработчиков и исходная URI
в результате не сохраняются. `to_dict()` возвращает JSON-совместимые данные.

| Категория | Код | Причина |
| --- | --- | --- |
| `invalid_request` | `invalid_command` | Неверный тип команды/поля или сочетание селекторов |
| `invalid_request` | `unsupported_contract_version` | Другая версия команды |
| `invalid_input` | `invalid_protocol_selector` | Неверная форма идентификатора протокола или URI-схемы |
| `invalid_input` | `invalid_engine_selector` | Неверная форма идентификатора движка |
| `unsupported` | `unknown_protocol` | Тип профиля не зарегистрирован |
| `unsupported` | `unknown_uri_scheme` | Схема не зарегистрирована |
| `unsupported` | `unsupported_protocol_capability` | У модуля нет обработчика операции |
| `unsupported` | `unknown_engine` | Движок не зарегистрирован |
| `unsupported` | `unsupported_engine_protocol` | У движка нет регистрации для протокола |
| `unsupported` | `unsupported_engine_capability` | Нет операции для выбранной пары |
| `source_failed` | `registry_failed` | Неожиданный сбой чтения реестра |
| `invalid_source_data` | `invalid_registry_data` | Реестр сообщил не предусмотренный контрактом отказ |

Сообщения статические, без пользовательских значений и текста исключений.
`KeyboardInterrupt` и `SystemExit` распространяются.

## Контракт регистрации

`ProtocolModule[ParametersT]` хранит идентификатор, tuple URI-схем,
тип модели параметров, tuple `ProtocolField` и необязательные обработчики
`parse_uri(str) -> ParametersT`, `validate_parameters(ParametersT) -> None`.
Набор возможностей вычисляется из наличия этих обработчиков. Парсер и
валидатор отвечают за соответствие возвращаемой модели и проверку её
параметров; регистрация не исполняет их для проверки.

`ProtocolRegistry((module, ...))` создаёт снимок состава. `by_protocol()` и
`by_uri()` возвращают модуль для доверенного вызывающего кода, а
`require(module, capability)` проверяет его принадлежность реестру и
операцию. Прямой доступ к обработчику и его результату не является безопасным
представлением для интерфейса.

`EngineBinding` содержит ID движка, ID протокола и tuple пар
`(EngineCapability, callable)`. Возможности: `generate_config`, `check_config`,
`probe`, `start`, `stop`. `EngineRegistry.resolve()` проверяет точную тройку;
`binding.operation()` возвращает обработчик без запуска. Сигнатуры,
предусловия и подтверждение выполнения принадлежат конкретному адаптеру и
вызывающему сценарию. Регистрация не подтверждает совместимость окружения.
Один протокол может обслуживаться разными движками и наоборот.

Дубли протокола, URI-схемы и пары движок/протокол отклоняются; порядок
регистрации не разрешает неоднозначность. Списки вместо tuple, повторы
операций, неверные метаданные и строки вместо обработчиков запрещены.
Прямой API сообщает `RegistryError` со статическим `RegistryErrorCode`.
Его `__context__` и `__cause__` не удерживают чужую цепочку исключений;
при ожидаемом отказе `by_uri()` его кадры не удерживают исходную ссылку.
Остальные собственные traceback, locals и дампы объектов безопасной
диагностикой не являются. Метаданные регистрации — открытые сведения поставки,
в них нельзя помещать секреты.

## Локальные тесты

```sh
python3 -I -S -B -m unittest discover -s tests -p 'test_protocol*.py' -v
```

Проверяются второй искусственный протокол, URI-псевдонимы, независимый выбор
движка, дубли, отказы и приватность результата. Сценарии выполняются под
запретом терминала, файлов, сети и процессов; обработчики не вызываются при
проверке возможностей.
