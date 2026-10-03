# Политики Keenetic и определение ID

`keenvpn.domain.keenetic_policy` описывает действующий список политик Keenetic
и находит ID политики по её описанию. Модели работают в памяти: они не читают
роутер, не создают, не удаляют и не изменяют политики и не назначают их
устройствам. Список передаётся готовым — из адаптера или из тестового источника.

## Модель

Роутер хранит политику под техническим именем (`Policy2`; в RCI это поле `name`)
и описанием, которое видит пользователь (`xkeen`). Имя назначает роутер,
на другой установке оно иное, поэтому в код не зашивается и ищется по описанию.

| Поле | Контракт |
| --- | --- |
| `KeeneticPolicy.policy_id` | Технический ID: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`; пробелы, управляющие символы и другие алфавиты отклоняются |
| `KeeneticPolicy.description` | Описание-метка либо `None`; принимается любая строка, пустая строка не заменяется `None` |
| `KeeneticPolicySet.policies` | Политики в порядке источника; list копируется в tuple, ID уникальны, принимаются только точные экземпляры `KeeneticPolicy` |

Описание может содержать личные данные, поэтому `repr()` политики его
скрывает, а `repr()` списка показывает только число политик. Разрешённые
подключения и остальные поля RCI в модель не переносятся: она служит для
чтения и сопоставления, а не для записи политики.

`KeeneticPolicySet.policy_ids` возвращает ID в порядке источника, `len()` —
число политик. Пустой список допустим: отсутствие политик — состояние роутера.

Готовые объекты можно проверить явно: `validate_policy(policy)`,
`validate_policy_set(policies)`, `validate_policy_id(value)` и
`validate_policy_description(value)` возвращают `None` или вызывают
`KeeneticPolicyError` с кодом из `KeeneticPolicyErrorCode`. Текст ошибки задан
заранее и не содержит переданных значений; цепочка внешнего исключения
к ошибке не присоединяется.

## Определение ID

`resolve_policy(policies, description, *, selected_policy_id=None)` сравнивает
описание с описаниями списка точно: без изменения регистра, обрезки пробелов
и нормализации Unicode. Описание для поиска — непустая строка до 256 символов
без управляющих символов, суррогатов, символов частного использования
и разделителей строк U+2028/U+2029; `None` в описании политики не совпадает
ни с чем.

| Исход `PolicyResolution.outcome` | Условие | `policy_id` | `candidates` |
| --- | --- | --- | --- |
| `resolved` | Ровно одно совпадение либо подтверждённый выбор | ID политики | Все совпавшие ID |
| `missing` | Совпадений нет | `None` | Пусто |
| `ambiguous` | Два и больше совпадений | `None` | Все совпавшие ID в порядке источника |

При неоднозначности первая политика не выбирается: ID остаётся пустым,
а выбор делает пользователь. Подтверждение передаётся в `selected_policy_id`
и принимается только из текущих `candidates`. Выбор политики с другим
описанием, несуществующего ID или устаревшего кандидата даёт
`KeeneticPolicyError` с кодом `policy_selection_mismatch`, чтобы прежний выбор
не привязал другую политику. Подтверждение единственного совпадения тоже
допустимо. Если совпадений нет, выбор не рассматривается и исход — `missing`.

`PolicyResolution` дополнительно содержит `policy_count` — число политик
в списке — и `selected_by_user`: ID подтверждён явным выбором, а не единственным
совпадением. Свойство `resolved` истинно только для `resolved`. Противоречивое
сочетание полей отклоняется кодом `invalid_policy_resolution`.

```python
from keenvpn.domain.keenetic_policy import KeeneticPolicy, KeeneticPolicySet, resolve_policy

# Искусственные значения; реальный список читает адаптер роутера.
policies = KeeneticPolicySet((
    KeeneticPolicy("Policy0", "NoVPN"),
    KeeneticPolicy("Policy2", "xkeen"),
    KeeneticPolicy("Policy5", "xkeen"),
))
ambiguous = resolve_policy(policies, "xkeen")
assert ambiguous.outcome.value == "ambiguous"
assert ambiguous.policy_id is None
assert ambiguous.candidates == ("Policy2", "Policy5")

confirmed = resolve_policy(policies, "xkeen", selected_policy_id="Policy5")
assert confirmed.policy_id == "Policy5"
assert confirmed.selected_by_user is True

assert resolve_policy(policies, "NoVPN").policy_id == "Policy0"
assert resolve_policy(policies, "XKeen").outcome.value == "missing"
```

| Код `KeeneticPolicyErrorCode` | Когда возникает |
| --- | --- |
| `invalid_policy_id` | ID политики или выбранный ID не соответствует формату |
| `invalid_policy_description` | Описание политики не строка либо описание для поиска недопустимо |
| `invalid_policy` | В списке объект другого типа или подкласс `KeeneticPolicy` |
| `invalid_policies` | Список не tuple моделей либо передан не `KeeneticPolicySet` |
| `duplicate_policy_id` | Повтор ID в списке |
| `invalid_policy_resolution` | Противоречивые поля `PolicyResolution` |
| `policy_selection_mismatch` | Выбранный ID не входит в текущие совпадения |

## Безопасный результат

`PolicyResolution.to_diagnostic()` возвращает `outcome`, `policy_id`,
`candidates`, `policy_count` и `selected_by_user`. Описания политик
в результат не входят. `repr()` показывает исход и число кандидатов.
Прикладной сценарий [`ResolveKeeneticPolicy`](application.md#определение-политики-keenetic)
возвращает те же поля через структурированный результат.

Успешное определение ID подтверждает только совпадение описания в переданном
списке. Оно не проверяет разрешённые подключения политики, назначения
устройств, работу XKeen или VPN и не меняет роутер.

## Локальная проверка

```sh
python3 -I -S -B -m unittest discover -s tests -p test_keenetic_policy.py -v
python3 -I -S -B -m unittest discover -s tests -p test_application_keenetic_policies.py -v
```

Тесты используют искусственные описания и
[обезличенный снимок](../tests/fixtures/router_snapshot/README.md), из которого
`tests/support/snapshot.py` собирает список политик. Роутер и сеть не требуются.
