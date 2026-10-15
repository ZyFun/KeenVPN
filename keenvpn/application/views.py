"""Общие помощники безопасных представлений прикладных сценариев.

Представления — frozen dataclass со слотами без `__dict__`. Они строятся из
безопасной диагностики доменных моделей и превращаются в JSON-совместимые
словари для CLI и будущего Web. Здесь нет доменных данных, секретов
и форматирования текста: только перенос полей по их объявлению.
"""


def view_fields(view_type: type, values: dict[str, object]) -> dict[str, object]:
    """Выбрать из диагностики только поля представления в порядке их объявления.

    Отсутствующее поле — ошибка согласованности кода, а не данных источника:
    диагностика доменной модели и представление объявлены вместе.
    """
    return {name: values[name] for name in view_type.__dataclass_fields__}


def view_dict(view: object) -> dict[str, object]:
    """Снять поля frozen dataclass со слотами, у которого нет `__dict__`."""
    return {name: getattr(view, name) for name in view.__dataclass_fields__}
