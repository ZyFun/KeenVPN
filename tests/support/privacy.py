"""Проверки, что результаты и кадры не удерживают приватные данные."""

import gc
import traceback
import types


def reachable(root: object) -> list[object]:
    """Объекты, достижимые из результата, без обхода классов и модулей."""
    seen, stack, found = set(), [root], []
    while stack:
        item = stack.pop()
        if id(item) in seen or isinstance(item, (type, types.ModuleType, types.FunctionType)):
            continue
        seen.add(id(item))
        found.append(item)
        stack.extend(gc.get_referents(item))
    return found


def frame_locals(error: BaseException, module_suffix: str) -> list[str]:
    """Вернуть repr локальных переменных кадров модуля из traceback ошибки.

    Пустой результат считается ошибкой теста: иначе после переименования
    модуля проверка проходила бы, не просмотрев ни одного кадра.
    """
    snapshot = traceback.TracebackException.from_exception(error, capture_locals=True)
    frames = [repr(frame.locals) for frame in snapshot.stack if frame.filename.endswith(module_suffix)]
    if not frames:
        raise AssertionError("В traceback нет кадров проверяемого модуля.")
    return frames
