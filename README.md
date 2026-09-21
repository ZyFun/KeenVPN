# KeenVPN

В репозитории доступны две локальные утилиты на Python:

| Утилита | Назначение |
|---|---|
| [check_python.py](scripts/check_python.py) | Проверка версии интерпретатора, модулей стандартной библиотеки и отдельных API |
| [audit_entware.py](scripts/audit_entware.py) | Статический аудит локального индекса и архивов пакетов Entware |

Утилиты не устанавливают пакеты, не настраивают VPN и не меняют конфигурацию роутера. Успешный результат относится только к выполненным проверкам, а не к готовности VPN или оборудования.

## Запуск

Используйте CPython 3.12 или новее в пределах стабильных выпусков Python 3 на macOS или Linux. Команды выполняются из корня репозитория; сторонние Python-библиотеки не нужны.

Проверка Python:

```sh
python3 -I -S -B scripts/check_python.py
```

Аудит подготовленных локальных файлов Entware:

```sh
python3 -I -S -B scripts/audit_entware.py /path/to/Packages /path/to/ipk-directory
```

Описание входных данных, проверок и кодов завершения:

- [Диагностика Python](docs/python-runtime.md).
- [Офлайн-аудит пакетов Entware](docs/entware-runtime.md).

## Тесты

```sh
python3 -I -S -B -m unittest discover -s tests -v
```

Тесты используют искусственные данные и [обезличенные фикстуры конфигурации](tests/fixtures/router_snapshot/README.md). Сеть и роутер не требуются.

## Безопасность и участие

Не публикуйте пароли, VPN-ссылки, токены, закрытые ключи и реальные приватные конфигурации. Для уязвимостей используйте [приватное сообщение](https://github.com/ZyFun/KeenVPN/security/advisories/new).

[Политика безопасности](SECURITY.md) · [Правила участия](CONTRIBUTING.md).

## Лицензия

Код и документация KeenVPN распространяются по [Apache License 2.0](LICENSE). [Сведения о сторонних компонентах](THIRD_PARTY_NOTICES.md).
