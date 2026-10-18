"""Поиск в списках меню по показанному тексту строк.

Запрос сравнивается только с текстом строки в том виде, в каком меню её
выводит: после фильтров представлений и без номера. Поэтому совпасть может
лишь то, что уже видно на экране; скрытые сценарием значения в поиске не
участвуют. Запрос и текст приводятся к NFKC без учёта регистра, запрос делится
на слова, и каждое слово должно входить в строку подстрокой. Запрос не
сохраняется и в вывод не попадает.
"""

from dataclasses import dataclass
import unicodedata


MAX_QUERY_CHARS = 64
"""Предел запроса в символах до и после нормализации; это не больше 256 байт UTF-8."""
MAX_QUERY_WORDS = 8
"""Предел числа слов запроса."""


def normalize(text: str) -> str:
    """Привести текст к NFKC без учёта регистра: полноширинные и прописные формы совпадают с обычными."""
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", text).casefold())


def is_number_like(text: object) -> bool:
    """Строка из одних цифр любой письменности после NFKC: это попытка ввести номер, а не запрос."""
    if type(text) is not str:
        return False
    stripped = text.strip()
    return stripped != "" and normalize(stripped).isdecimal()


@dataclass(frozen=True, slots=True)
class SearchQuery:
    """Разобранный запрос: нормализованные слова в порядке ввода."""

    words: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.words) is not tuple
            or not 1 <= len(self.words) <= MAX_QUERY_WORDS
            or any(type(word) is not str or not word or " " in word for word in self.words)
        ):
            raise ValueError("Запрос поиска — от одного до восьми непустых слов.")


def parse_query(text: object) -> SearchQuery | None:
    """Разобрать запрос поиска или вернуть None, если он пуст, слишком длинный или с недопустимыми символами.

    Допустимы печатные символы и обычный пробел, до 64 символов до и после
    нормализации и до восьми слов. Строку из одних цифр вызывающий код
    считает номером и проверяет `is_number_like` до разбора запроса.
    """
    if type(text) is not str:
        return None
    stripped = text.strip()
    # isprintable() отклоняет управляющие символы, ESC, табуляцию, суррогаты, символы
    # частного использования и все разделители, кроме обычного пробела.
    if not stripped or len(stripped) > MAX_QUERY_CHARS or not stripped.isprintable():
        return None
    normalized = normalize(stripped)
    if len(normalized) > MAX_QUERY_CHARS or not normalized.isprintable():
        return None
    words = tuple(word for word in normalized.split(" ") if word)
    if not 1 <= len(words) <= MAX_QUERY_WORDS:
        return None
    return SearchQuery(words)


def matches(query: SearchQuery, normalized_text: str) -> bool:
    """Проверить, что каждое слово запроса входит в нормализованный текст строки."""
    return all(word in normalized_text for word in query.words)
