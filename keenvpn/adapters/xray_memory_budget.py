"""Консервативный бюджет страниц для закрытого профиля Linux AArch64.

Координатор резервирует бюджет до допуска syscall и не возвращает его после
ошибок, munmap или PROT_NONE. Сам счётчик не является механизмом ОС-изоляции:
исполнитель должен контролировать все потоки, начальные отображения и остальные
пути появления пользовательских страниц, включая собственные записи в tracee.
"""


PAGE_SIZE = 4096
UINT64_MAX = (1 << 64) - 1
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 2
MAP_FIXED = 0x10
MAP_ANONYMOUS = 0x20
MAP_NORESERVE = 0x4000
_MAPPING_FLAGS = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE


class UnsupportedMemoryOperation(Exception):
    """Операция выходит за проверенный профиль; её нельзя передавать ядру."""


class MemoryBudgetExceeded(Exception):
    """До исполнения операции исчерпан бюджет потенциально резидентных страниц."""


def _integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise UnsupportedMemoryOperation
    return value


def _rounded(value: int) -> int:
    result = (_integer(value) + PAGE_SIZE - 1) & -PAGE_SIZE
    if result > UINT64_MAX:
        raise UnsupportedMemoryOperation
    return result


def _range(address: int, length: int) -> None:
    if _integer(address) + _integer(length) > UINT64_MAX:
        raise UnsupportedMemoryOperation


def _protection(value: int) -> None:
    if _integer(value) & ~(PROT_READ | PROT_WRITE | PROT_EXEC):
        raise UnsupportedMemoryOperation


class XrayMemoryBudget:
    """Один монотонный бюджет общего mm; им владеет единственный координатор.

initial_bytes резервируется до exec и включает верхнюю границу начальных
отображений ELF, VDSO/VVAR и полный разрешённый рост начального стека.
Потоки одного mm используют тот же экземпляр. Создание нового mm запрещает
исполнитель. Статус syscall не является основанием для возврата бюджета.
"""

    def __init__(self, limit: int, initial_bytes: int) -> None:
        self._limit = _integer(limit)
        self._used = 0
        self._break_ceiling: int | None = None
        if self._limit == 0:
            raise UnsupportedMemoryOperation
        self._reserve(initial_bytes)

    @property
    def used(self) -> int:
        return self._used

    def _reserve(self, length: int) -> None:
        amount = _rounded(length)
        if amount > self._limit - self._used:
            raise MemoryBudgetExceeded
        self._used += amount

    def set_initial_break(self, address: int) -> None:
        """Принять начальный brk нового ELF-mm до исполнения его пользовательского кода."""
        if self._break_ceiling is not None or _integer(address) == 0:
            raise UnsupportedMemoryOperation
        self._break_ceiling = _rounded(address)

    def before_mmap(self, address: int, length: int, protection: int, flags: int) -> None:
        """Зарезервировать рост до mmap; сторонние/изменяемые fd запрещает исполнитель."""
        _range(address, length)
        _protection(protection)
        if (_integer(flags) & ~_MAPPING_FLAGS or not flags & MAP_PRIVATE or length == 0
                or flags & MAP_FIXED and address % PAGE_SIZE):
            raise UnsupportedMemoryOperation
        # Новая обычная anonymous PROT_NONE не создаёт пользовательских страниц.
        # Ни MAP_POPULATE, ни расширяемые VMA закрытый набор флагов не допускает.
        if protection or not flags & MAP_ANONYMOUS:
            self._reserve(length)

    def before_mprotect(self, address: int, length: int, protection: int) -> None:
        """Полностью оплатить доступный диапазон, включая возможный частичный эффект."""
        _range(address, length)
        _protection(protection)
        if address % PAGE_SIZE:
            raise UnsupportedMemoryOperation
        if protection:
            self._reserve(length)

    def before_brk(self, address: int) -> None:
        """Оплатить рост сверх прежнего максимума; запрос/уменьшение не возвращают бюджет."""
        if _integer(address) == 0:
            return
        if self._break_ceiling is None:
            raise UnsupportedMemoryOperation
        end = _rounded(address)
        if end > self._break_ceiling:
            self._reserve(end - self._break_ceiling)
            self._break_ceiling = end
