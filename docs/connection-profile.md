# Общий профиль подключения

`keenvpn.domain.profile` отделяет идентичность профиля от типизированных
параметров протокола. Модели работают в памяти, не выбирают движок и не читают
конфигурационные файлы.

## Структура

`ProfileIdentity` сначала проверяет `format_version`: положительное целое,
`bool` не принимается. Остальные поля проверяются по следующему контракту
только для поддержанной версии `PROFILE_FORMAT_VERSION = 1`:

| Поле | Контракт |
| --- | --- |
| `profile_id` | Непустой `uuid.UUID`, назначенный вызывающим кодом; строка и нулевой UUID отклоняются |
| `name` | Имя либо `None`; непустая строка до 256 символов без символов категорий `Cc`, `Cs`, `Co`, `Zl`, `Zp` и bidi-управляющих U+202A–U+202E/U+2066–U+2069 |
| `protocol` | Идентификатор доверенного модуля: `[a-z][a-z0-9_-]{0,31}` |
| `format_version` | Положительное целое, `bool` не принимается; по умолчанию `PROFILE_FORMAT_VERSION = 1` |

Имя сохраняется без нормализации и не является ключом: одинаковые имена
допустимы. Чтение не генерирует ID, переименование не требует смены ID.
Разделители строк U+2028 и абзацев U+2029 запрещены в любой позиции имени.
ZWJ/ZWNJ допускаются, включая составные эмодзи и текст с соединителями.
Неназначенные символы `Cn` также допускаются: их назначение в новой базе
Unicode само по себе не меняет допустимость имени.
Версия оболочки профиля независима от `CONTRACT_VERSION` команд application.
Модели сохраняют положительную неизвестную версию и её исходные поля без
валидации по правилам v1. Сценарий просмотра отклоняет такую версию явно,
прежде чем интерпретировать имя, протокол, ID или параметры. Это сохраняет
данные для отказа `unsupported` без предположений об их формате.

`ConnectionProfile[ParametersT]` содержит `identity` и `parameters`.
Для версии 1 параметры соответствуют структурному контракту `ProfileParameters`:
предоставляют строковый `protocol`, совпадающий с `identity.protocol`.
Параметры сохраняются как исходный объект. Для версии 1 словари вместо
типизированной модели не принимаются.
Для неизвестной версии параметры сохраняются без проверки и обращения к их
полям или методам.
Общий профиль не разбирает URI, не проверяет значения полей конкретного
протокола и не подтверждает его поддержку движком. Эти проверки принадлежат
доверенному коду, предоставляющему модель.

Оболочка и идентичность неизменяемы. Оболочка не замораживает вложенный объект:
доверенный источник отвечает за модель параметров. Для копии с другим именем
можно использовать `dataclasses.replace`; исходный профиль сохраняется.

Готовые модели можно проверить явно: `validate_profile_identity(identity)`
проверяет поля идентичности, а `validate_profile(profile)` — идентичность
и общую структуру параметров. Обе функции возвращают `None` при успехе
или вызывают `ProfileValidationError`. Они не нормализуют имя, не меняют поля
и не заменяют вложенные объекты. Эти же проверки используются при создании
моделей и при просмотре профиля; повторная проверка не вызывает хуки создания.

```python
from dataclasses import replace
from uuid import UUID

from keenvpn.adapters.trojan_uri import parse_trojan_uri
from keenvpn.domain.profile import ConnectionProfile, ProfileIdentity

# Искусственные данные; реальную ссылку передавайте через закрытый ввод.
connection = parse_trojan_uri(
    "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443?security=tls&type=ws#URI-name"
)
identity = ProfileIdentity(
    UUID("c0000000-0000-4000-8000-000000000001"), "Пример профиля", "trojan",
)
profile = ConnectionProfile(identity, connection)
renamed = replace(profile, identity=replace(identity, name="Другое имя"))
assert renamed.identity.profile_id == profile.identity.profile_id
assert renamed.parameters is connection
assert connection.name == "URI-name"
```

`TrojanConnection` и результат `parse_trojan_uri()` сохраняют прежние поля
и поведение. `TrojanConnection.name` — имя из URI; `ProfileIdentity.name` — имя
профиля. При такой явной сборке они независимы, автоматически не синхронизируются.

## Сборка через реестр

`application.profile_preparation.ConnectionProfileFactory` собирает профиль
в памяти через переданный доверенный реестр. ID, имя, протокол и версия
передаются в готовой `ProfileIdentity`; фабрика не назначает новый ID.

- `from_parameters(identity, parameters)` оборачивает существующую модель.
  Для версии 1 проверяются идентичность, принадлежность параметров типу
  зарегистрированного модуля и общая структура профиля. Подклассы модели
  параметров допускаются, дополнительные поля сохраняются в исходном объекте.
  Парсер и протокольный валидатор не вызываются: сборка не объявляет
  произвольную существующую модель валидной URI или рабочим VPN.
- `from_link(identity, link)` принимает URI как `SecretValue`, выбирает модуль
  по `identity.protocol`, требует `parse_uri` и вызывает его парсер ровно один
  раз. Принадлежность URI протоколу и параметры проверяет сам парсер.
  Для Trojan `from_link` вызывает `TrojanLinkParser` из поставки: значения,
  defaults, декодирование, сообщения и коды отказов совпадают с
  [разбором Trojan URI](trojan-uri.md).

Оба метода возвращают приватную `ConnectionProfile`, предназначенную для
внутреннего кода. Интерфейс использует безопасный сценарий
[`InspectProfileLink`](application.md#проверка-сборки-профиля-из-ссылки).
Фабрика не пишет файлы, не импортирует Xray/XKeen-конфигурацию и не применяет
изменения. Готовые параметры и секреты не копируются и не нормализуются.
Имя из URI сохраняется в параметрах, а имя профиля задаётся отдельно.

```python
from uuid import UUID

from keenvpn.adapters.protocols import bundled_protocols
from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.profile_preparation import ConnectionProfileFactory
from keenvpn.domain.connection import SecretValue
from keenvpn.domain.profile import ProfileIdentity

identity = ProfileIdentity(UUID("c0000000-0000-4000-8000-000000000001"), None, "trojan")
uri = "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443?security=tls&type=ws#URI-name"
original = TrojanLinkParser().parse(uri)
factory = ConnectionProfileFactory(bundled_protocols())
profile = factory.from_parameters(identity, original)
assert profile.parameters is original
assert profile.parameters.password is original.password
assert profile.identity.name is None
assert profile.parameters.name == "URI-name"
parsed = factory.from_link(identity, SecretValue(uri))
assert parsed.identity is identity
assert parsed.parameters.name == original.name
```

Неизвестная положительная версия при `from_parameters` сохраняется вместе
с идентичностью и параметрами без обращения к реестру и полям параметров.
Просмотр по ID и `from_link` явно отклоняют её как неподдержанную.
Неподдерживаемая модель не преобразуется автоматически: отказ оставляет
исходный объект вызывающему коду. Сериализации и миграции файлов нет.

При отказе фабрика вызывает `ProfilePreparationError` с безопасной `detail`
типа `ErrorDetail`. Ошибки реестра и доверенного парсера сохраняют существующие
коды. Неверная идентичность даёт `invalid_input / invalid_profile_identity`,
ошибки её полей — `invalid_input / invalid_profile_model` с доменной `reason`.
Неверный секретный ввод — `invalid_input / invalid_profile_link`, неверный
тип или протокол параметров — `invalid_source_data / invalid_connection_model`.
Непредвиденный отказ заменяется статическим
`source_failed / profile_preparation_failed`. Неизвестная версия при разборе
URI — `unsupported / unsupported_profile_format_version`.

Новые отказы не удерживают исходные исключения или внутренние кадры разбора;
приватные аргументы удаляются из собственных кадров отказа фабрики.
`KeyboardInterrupt` и `SystemExit` распространяются. Объекты вызывающего кода,
доверенных callbacks, прямой доступ к параметрам и дампы памяти безопасной
диагностикой не являются.

## Диагностика и ошибки

`repr()` идентичности и профиля скрывает содержимое. `to_diagnostic()` профиля
для версии 1 возвращает только `profile_id` в строковой форме, `protocol`,
`format_version` и `has_name`. Метод не вызывает диагностику параметров. Имя, адрес, пароль,
путь, полная ссылка и сама модель параметров в результат не входят.
ID и идентификатор протокола — открытые служебные метаданные; секреты в них
не передаются. Прямой доступ к полям, `asdict()` и дамп объектов не являются
безопасным отчётом.

Для неизвестной положительной версии `to_diagnostic()` возвращает только
`format_version`; остальные метаданные и параметры не интерпретируются.
Некорректный номер версии отклоняется до чтения полей версии 1.

Ошибка структуры — `ProfileValidationError` со статическим русским сообщением
и `code` типа `ProfileErrorCode`:

- `invalid_profile_id`, `invalid_profile_name`, `invalid_profile_protocol`,
  `invalid_profile_format_version` — недопустимое общее поле;
- `invalid_profile_identity` — вместо идентичности передан другой тип;
- `invalid_profile_parameters` — объект не предоставляет строковый протокол
  или получение протокола завершилось исключением;
- `profile_protocol_mismatch` — протокол идентичности отличается от параметров.

Отказы валидации отделяются от активного исключения вызывающего кода:
`__context__` и `__cause__` равны `None`, в том числе при создании или
повторной проверке профиля внутри внешнего `except`. Ожидаемое исключение
параметров заменяется отказом без исходной цепочки. Стандартный traceback
и `logger.exception()` не печатают сообщения этих внешних исключений.

Собственный traceback ошибки, локальные переменные его кадров и объекты
вызывающего кода не очищаются: дамп с локальными переменными не является
безопасной диагностикой. Внешнее исключение, которое хранит вызывающий код,
не изменяется. `KeyboardInterrupt` и `SystemExit` не перехватываются.

Профиль используется сценарием
[`InspectConnectionProfile`](application.md#просмотр-профиля-по-id).

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_profile.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_profiles.py -v
python3 -I -S -B -m unittest discover -s tests -p test_profile_preparation.py -v
```

Проверяются стабильность ID, независимость имени и параметров, ошибки структуры,
работа с Trojan и искусственной моделью другого протокола, приватность
и выполнение без терминала, файлов, сети и процессов. Искусственная модель
проверяет общий контракт, а не поддержку дополнительного VPN-протокола.
