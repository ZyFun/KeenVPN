"""Предварительная граница ELF/стека и проверка нового mm на остановке exec.

Используется только static ET_EXEC AArch64, закреплённый SHA-256 поставки.
Для Linux 4.9 native VDSO/VVAR — общие образы ядра фиксированного размера:
размер читается у native координатора до exec, затем сверяется у ребёнка.
Новый mm состоит из LOAD, ограниченного RLIMIT_STACK стека и этих образов.
"""

from dataclasses import dataclass
import struct

from keenvpn.adapters.xray_candidate_test import IsolationUnavailable
from keenvpn.adapters.xray_memory_budget import PAGE_SIZE, UINT64_MAX


STACK_LIMIT = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class Mapping:
    start: int
    end: int
    permissions: str
    name: str


def parse_maps(data: bytes) -> tuple[Mapping, ...]:
    """Разобрать ограниченный снимок proc/maps, не выводя пути и адреса."""
    if type(data) is not bytes or not data or len(data) > 256 * 1024:
        raise IsolationUnavailable
    result = []
    last_end = 0
    try:
        for line in data.decode('ascii').splitlines():
            fields = line.split(maxsplit=5)
            start, end = (int(v, 16) for v in fields[0].split('-'))
            permissions = fields[1]
            if (not last_end <= start < end <= UINT64_MAX or start % PAGE_SIZE or end % PAGE_SIZE
                    or len(fields) < 5 or len(permissions) != 4 or permissions[3] not in 'ps'
                    or permissions[0] not in 'r-' or permissions[1] not in 'w-'
                    or permissions[2] not in 'x-'):
                raise IsolationUnavailable
            result.append(Mapping(start, end, permissions, fields[5] if len(fields) == 6 else ''))
            last_end = end
    except (ValueError, UnicodeError, IndexError):
        raise IsolationUnavailable from None
    if not result:
        raise IsolationUnavailable
    return tuple(result)


def auxiliary_sizes(maps: tuple[Mapping, ...]) -> tuple[tuple[str, int], ...]:
    """Оба процесса проверяются как native; compat vdso и неизвестные образы запрещены."""
    sizes = {}
    for item in maps:
        if item.name in ('[vdso]', '[vvar]'):
            if item.name in sizes:
                raise IsolationUnavailable
            sizes[item.name] = item.end - item.start
    if '[vdso]' not in sizes or not 0 < sum(sizes.values()) <= 1024 * 1024:
        raise IsolationUnavailable
    return tuple(sorted(sizes.items()))


def load_ranges(header: bytes, file_size: int) -> tuple[tuple[int, int], ...]:
    """Вычислить полные диапазоны LOAD проверенного статического ELF без его исполнения."""
    try:
        fields = struct.unpack_from('<16sHHIQQQIHHHHHH', header)
        identity, kind, machine, version, entry, offset = fields[:6]
        if (identity[:9] != b'\x7fELF\x02\x01\x01\x00\x00' or kind != 2 or machine != 183 or version != 1
                or fields[7] != 0 or fields[8] != 64 or fields[9] != 56 or not 0 < fields[10] <= 16
                or offset < 64 or offset + fields[10] * 56 > len(header)):
            raise IsolationUnavailable
        ranges = []
        executable_entry = stack_found = False
        for index in range(fields[10]):
            part = struct.unpack_from('<IIQQQQQQ', header, offset + index * 56)
            ptype, flags, file_offset, address, _, size, memory_size, alignment = part
            if ptype == 1:
                if (flags not in (4, 5, 6) or not 0 < memory_size or size > memory_size
                        or file_offset + size > file_size or address + memory_size > UINT64_MAX
                        or address % PAGE_SIZE != file_offset % PAGE_SIZE
                        or alignment < PAGE_SIZE or alignment & (alignment - 1)):
                    raise IsolationUnavailable
                start = address & -PAGE_SIZE
                end = (address + memory_size + PAGE_SIZE - 1) & -PAGE_SIZE
                if end > UINT64_MAX:
                    raise IsolationUnavailable
                ranges.append((start, end))
                executable_entry |= bool(flags & 1 and address <= entry < address + size)
            elif ptype == 0x6474E551:  # GNU_STACK, только NX.
                if stack_found or flags != 6:
                    raise IsolationUnavailable
                stack_found = True
            elif ptype != 6:  # PHDR не создаёт самостоятельного отображения.
                raise IsolationUnavailable
        ranges.sort()
        if (not ranges or not executable_entry or not stack_found
                or any(previous[1] > current[0] for previous, current in zip(ranges, ranges[1:]))):
            raise IsolationUnavailable
        return tuple(ranges)
    except (struct.error, ValueError, TypeError):
        raise IsolationUnavailable from None


def initial_break(data: bytes, expected_pid: int) -> int:
    """Поле start_brk (47) читается на exec-stop, до первого пользовательского syscall."""
    try:
        prefix, fields = data.rsplit(b') ', 1)
        if int(prefix.split(b' (', 1)[0]) != expected_pid:
            raise IsolationUnavailable
        value = int(fields.split()[44])  # Первый элемент — поле 3, state.
        if not 0 < value <= UINT64_MAX or value % PAGE_SIZE:
            raise IsolationUnavailable
        return value
    except (ValueError, IndexError, TypeError):
        raise IsolationUnavailable from None


@dataclass(frozen=True, slots=True, repr=False)
class InitialMemory:
    """Создаётся до exec; bytes резервируется до передачи управления загрузчику."""

    loads: tuple[tuple[int, int], ...]
    auxiliary: tuple[tuple[str, int], ...]

    @property
    def bytes(self) -> int:
        return sum(end - start for start, end in self.loads) + STACK_LIMIT + sum(size for _, size in self.auxiliary)

    def verify_exec(self, maps: tuple[Mapping, ...]) -> tuple[int, int]:
        """Подтвердить предпосылки до исполнения ELF и получить защищённый диапазон стека."""
        if auxiliary_sizes(maps) != self.auxiliary:
            raise IsolationUnavailable
        stack = None
        for item in maps:
            if item.name in ('[vdso]', '[vvar]'):
                continue
            if item.name == '[stack]':
                if (stack is not None or item.end - item.start > STACK_LIMIT or item.end < STACK_LIMIT
                        or item.permissions != 'rw-p'):
                    raise IsolationUnavailable
                stack = item.end - STACK_LIMIT, item.end
            elif (item.permissions[3] != 'p'
                  or not any(low <= item.start < item.end <= high for low, high in self.loads)):
                raise IsolationUnavailable
        if stack is None or any(low < stack[1] and high > stack[0] for low, high in self.loads):
            raise IsolationUnavailable
        return stack
