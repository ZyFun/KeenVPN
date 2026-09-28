# Статическое объяснение маршрута

`keenvpn.domain.routing_explanation.explain_route(policy, context, geo_matcher=None)`
возвращает предварительный расчёт для [модели правил](routing-model.md).
Проверяются точное имя или имя с поддоменами, IPv4/IPv6 и CIDR, GeoIP и GeoSite.
Обход идёт по сохранённому порядку до первого совпадения либо неизвестности.
Отключённые правила отражаются как пропущенные. Служебные проверяются первыми
на общих основаниях. Если все включённые условия заведомо не совпали,
выбирается явное финальное действие.

Это API Python для данных в памяти. Оно не запускает Xray, не делает DNS-запросов,
не читает геобазы и не меняет конфигурацию. Результат не подтверждает путь
реального трафика, работоспособность VPN или применимость конфигурации.

## Входные предположения

`RoutingContext` принимает только именованные аргументы. Источники задаются
Enum, обычные строки вместо них отклоняются.

| Поле | Смысл |
| --- | --- |
| `domain` | Нормализованное имя, которое считается доступным маршрутизации. Валидация и IDNA совпадают с `DomainCondition`; URL и IP вместо домена не принимаются. |
| `domain_source=DomainSource.DESTINATION` | Имя назначения считается видимым, без моделирования подмены через sniffing. Требует `domain`. Несовместимо с `ip_source=IPSource.DESTINATION`: назначение соединения — либо имя, либо IP. |
| `domain_source=DomainSource.SNIFFING` | Предполагается, что sniffing предоставил указанное имя. Требует `domain`. |
| `domain_source=DomainSource.UNAVAILABLE` | Имя считается недоступным, в том числе через sniffing. Требует `domain=None`; доменные условия дают `NO_MATCH`. |
| `domain_source=DomainSource.UNKNOWN` | Видимость неизвестна. Требует `domain=None`; доменные условия дают `UNKNOWN`. Это значение по умолчанию. |
| `ips` | Полный набор доступных этому расчёту адресов. List копируется в tuple; принимаются только отдельные IPv4/IPv6, без CIDR, зонального индекса или порта. IPv4-mapped IPv6 (`::ffff:192.0.2.10`) при проверке IP/CIDR сопоставляется как соответствующий IPv4-адрес, как в Xray. |
| `ip_source=IPSource.DESTINATION` | Ровно один переданный IP назначения. |
| `ip_source=IPSource.DNS` | Непустой набор, который считается полным результатом DNS, доступным всем IP-правилам этого расчёта. |
| `ip_source=IPSource.UNAVAILABLE` | Адреса явно недоступны: требуется `ips=()`, IP-условия дают `NO_MATCH`. |
| `ip_source=IPSource.UNKNOWN` | Адреса неизвестны: требуется `ips=None`, IP-условия дают `UNKNOWN`. Это значение по умолчанию. |

`UNKNOWN` не эквивалентен отсутствию совпадения. В частности, неизвестный DNS
или неподтверждённое имя из sniffing не позволяют пропустить раннее правило
и объявить выбранным более поздний DIRECT, VPN или BLOCK.

Расчёт делает один проход с фиксированными входными данными. Он не имитирует
`domainStrategy` Xray: `AsIs`, двухпроходный `IPIfNonMatch`, разрешение по
требованию `IPOnDemand`, повторный DNS, кеш или взаимодействие с `routeOnly`.
Их семантика описана в [документации Xray](https://xtls.github.io/en/config/routing.html#routingobject).
Передача `IPSource.DNS` означает явное предположение о доступных адресах,
а не автоматическое определение нужного режима. Для проверки нескольких
сценариев вызывающий код создаёт отдельный контекст для каждого.

```python
from keenvpn.domain.routing import DomainCondition, IPCondition, RoutingAction, RoutingRule
from keenvpn.domain.routing_policy import FinalRoutingRule, RoutingPolicy
from keenvpn.domain.routing_explanation import DomainSource, IPSource, RoutingContext, explain_route

policy = RoutingPolicy((
    RoutingRule(DomainCondition("example.test"), RoutingAction.VPN),
    RoutingRule(IPCondition("192.0.2.0/24"), RoutingAction.DIRECT),
), FinalRoutingRule(RoutingAction.BLOCK))

context = RoutingContext(
    domain="Sub.Example.Test.", domain_source=DomainSource.SNIFFING,
    ips=("192.0.2.10",), ip_source=IPSource.DESTINATION,
)
report = explain_route(policy, context)
assert report.selection.index == 0
assert report.selection.action is RoutingAction.VPN
assert len(report.steps) == 1  # Более позднее IP-правило не проверялось.
assert "sniffing" in report.assumptions[2]

# IP известен, но видимость имени неизвестна: раннее правило нельзя пропустить.
uncertain = explain_route(policy, RoutingContext(
    ips=("192.0.2.10",), ip_source=IPSource.DESTINATION,
))
assert uncertain.selection is None
assert uncertain.steps[0].result.value == "unknown"
```

## Источник GeoIP и GeoSite

Опциональный `geo_matcher(condition, values)` — доверенная функция. Она получает
точное `GeoIPCondition` или `GeoSiteCondition`, включая ссылку на базу и имя
набора, и tuple нормализованных значений: все доступные IP либо одно видимое имя.
Функция возвращает `GeoMatch(result, database)`:

- `MATCH`: хотя бы одно значение входит в указанный набор.
- `NO_MATCH`: все переданные значения проверены и не входят в него.
- `UNKNOWN`: база, набор или сведения для проверки отсутствуют либо неполны.

Источнику передаются нормализованные строки адресов без преобразования
IPv4-mapped IPv6 в IPv4.

`database` содержит метаданные фактически использованной базы. Тип и ссылка
должны совпасть с условием; известные `source`, `version`, `sha256` также
должны совпасть. Неизвестные поля можно уточнить в ответе. Если версия осталась
`None`, она остаётся неизвестной, а не выводится из имени файла. Модель сверяет
заявленные сведения; она не проверяет файл, подлинность или достоверность ответа.
Наличие метаданных без `geo_matcher` даёт `UNKNOWN`.

Результат обращения сохраняется в `step.database`: поля `kind`, `reference`,
`source`, `version`, `sha256` доступны для явного просмотра вызывающим кодом.
В том числе можно получить версии как `step.database.version` у шагов, где
`database is not None`. Более поздние, отключённые и непроверенные базы не
выдаются за использованные. `step.rule.condition.set_name` хранит проверенный
набор. Для ответа `UNKNOWN` метаданные относятся к обращению к источнику,
не к доказанному членству в наборе.

Доменная зона, страна IP и категория GeoSite независимы. Пример использует
искусственные данные: домен `.ru`, IP вне набора `ru`, совпадение GeoSite.

```python
from keenvpn.domain.routing import (
    DomainCondition, GeoDatabase, GeoDatabaseKind, GeoIPCondition,
    GeoSiteCondition, RoutingAction, RoutingRule,
)
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from keenvpn.domain.routing_explanation import (
    DomainSource, GeoMatch, IPSource, RoutingContext, explain_route,
)

ip_db = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip", version="ip-v1")
site_db = GeoDatabase(GeoDatabaseKind.GEOSITE, "fixture-sites", version="site-v2")
country = RoutingRule(GeoIPCondition(ip_db, "ru"), RoutingAction.DIRECT)
sites = RoutingRule(GeoSiteCondition(site_db, "test-services"), RoutingAction.BLOCK)
zone = RoutingRule(DomainCondition("ru"), RoutingAction.VPN)
policy = RoutingPolicy((country, sites, zone), FinalRoutingRule(RoutingAction.BLOCK))
context = RoutingContext(
    domain="service.example.ru", domain_source=DomainSource.DESTINATION,
    ips=("192.0.2.10",), ip_source=IPSource.DNS,
)

def fixture(condition, values):
    if isinstance(condition, GeoIPCondition):
        assert values == ("192.0.2.10",) and condition.set_name == "ru"
        return GeoMatch(MatchResult.NO_MATCH, ip_db)
    assert values == ("service.example.ru",) and condition.set_name == "test-services"
    return GeoMatch(MatchResult.MATCH, site_db)

report = explain_route(policy, context, geo_matcher=fixture)
assert report.selection.rule is sites
assert [step.database.version for step in report.steps] == ["ip-v1", "site-v2"]

earlier = explain_route(policy.move(2, 0), context, geo_matcher=fixture)
assert earlier.selection.rule is zone
assert all(step.database is None for step in earlier.steps)
```

Источник не вызывается для отключённых правил, неизвестного импорта,
невидимого/неизвестного имени, недоступных/неизвестных адресов, финального правила
или после остановки. Отсутствие I/O зависит также от реализации переданной
функции; API не изолирует её от сети и файловой системы.

## Результат и безопасный вывод

`RouteExplanation` хранит исходный `context`, неизменяемый tuple `steps` и
`selection`. Каждый шаг содержит индекс, исходное правило, результат, безопасную
причину `ExplanationReason` и использованную базу, если было обращение к источнику.
Индексы относятся к `policy.ordered_rules`, включая отключённые позиции.
Для пропущенного правила `result=None`; у неизвестного — `MatchResult.UNKNOWN`.
Первое неизвестное включённое условие завершает объяснение с `selection=None`.
Это отсутствие выбранного действия, а не отправка реального трафика в BLOCK.

`report.assumptions` явно сообщает ограничения расчёта, предположения о DNS,
видимости имени/sniffing и доверии к источнику геоданных. `to_diagnostic()`
возвращает JSON-совместимую трассу с этими ограничениями, типами условий,
позициями, признаками `enabled` и `protected` (у финального шага — `None`),
результатами и безопасными признаками метаданных. Значения доменов,
IP, категорий, ссылок, источников, версий и хешей в неё не входят: произвольные
строки могут содержать приватные данные. `repr()`/`str()` также скрывают поля.
Полные поля, `dataclasses.asdict()` и traceback с локальными переменными
не предназначены для безопасного журналирования.

Некорректный контекст вызывает `RoutingValidationError` с `CONTEXT`, `DOMAIN`
или `IP`. Конструкторы шагов и результата проверяют типы полей (`EXPLANATION`),
список шагов копируется в tuple. Их назначение — хранить результат `explain_route`;
ручное создание не проверяет истинность переданных совпадений.
Неверный ответ геоисточника, в том числе `RoutingValidationError` при
построении `GeoMatch` или `GeoDatabase` внутри источника, — `GEODATA_RESULT`.
Подмена типа, ссылки или известных метаданных базы — `GEODATA_MISMATCH`
(`geodata_database_mismatch`), прочее исключение источника — `MATCHER`.
Сырые ошибки источника не включаются в текст или цепочку нового исключения;
`KeyboardInterrupt` и `SystemExit` проходят наружу. Ошибки не заменяются
успешным финальным действием. Известные ошибки валидации подавляют внешний
контекст в обычном traceback, но сам внешний контекст не очищают.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_routing_explanation.py -v
```

Используются искусственные домены, документальные IP и управляемый источник.
Проверяются первое совпадение, точные имена/поддомены/IDNA, IPv4/IPv6/CIDR,
различие доменной зоны и геонаборов, приоритет исключений, неизвестные данные,
отключённые и служебные правила, версии баз, отказы источника и безопасный вывод.
С чистым источником проверяется отсутствие I/O. Реальный сетевой маршрут,
содержимое установленных геобаз и поведение Xray эти тесты не подтверждают.
