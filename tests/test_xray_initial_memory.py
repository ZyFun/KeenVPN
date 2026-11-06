"""Начальные отображения проверяются до передачи управления пользовательскому ELF."""

from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.xray_candidate_test import IsolationUnavailable
from keenvpn.adapters.xray_initial_memory import (
    InitialMemory, Mapping, STACK_LIMIT, auxiliary_sizes, initial_break, load_ranges, parse_maps,
)


def elf_header(*, machine=183, kind=2, flags=5, memory_size=4097, extra_type=0x6474E551):
    header = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01', kind, machine,
                         1, 0x10080, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    first = struct.pack('<IIQQQQQQ', 1, flags, 0, 0x10000, 0, 4096, memory_size, 4096)
    second = struct.pack('<IIQQQQQQ', extra_type, 6, 0, 0, 0, 0, 0, 8)
    return header + first + second


class InitialMemoryTests(unittest.TestCase):
    def test_static_load_counts_partial_last_page_and_zero_filled_bss(self):
        self.assertEqual(load_ranges(elf_header(), 4096), ((0x10000, 0x12000),))
        layout = InitialMemory(load_ranges(elf_header(), 4096), (('[vdso]', 8192), ('[vvar]', 4096)))
        self.assertEqual(layout.bytes, 8192 + STACK_LIMIT + 12288)

    def test_dynamic_other_abi_and_interpreter_are_rejected(self):
        for changes in ({'machine': 62}, {'kind': 3}, {'extra_type': 3}, {'flags': 7}):
            with self.assertRaises(IsolationUnavailable):
                load_ranges(elf_header(**changes), 4096)

    def test_elf_rejects_missing_file_bytes_or_wrapping_memory_range(self):
        for header, size in ((elf_header(), 4095), (elf_header(memory_size=(1 << 64) - 1), 4096),
                             (elf_header()[:-1], 4096), (elf_header(memory_size=1), 4096)):
            with self.assertRaises(IsolationUnavailable):
                load_ranges(header, size)

    def test_maps_parser_accepts_paths_with_spaces_without_exposing_them(self):
        maps = parse_maps(b'10000-12000 r-xp 00000000 00:01 1 /private input\n'
                          b'80000000-80002000 r-xp 00000000 00:00 0 [vdso]\n')
        self.assertEqual(maps[0].name, '/private input')
        self.assertNotIn('/private', repr(maps[0]))
        self.assertEqual(auxiliary_sizes(maps), (('[vdso]', 8192),))

    def test_maps_parser_rejects_overlaps_bad_alignment_and_oversize(self):
        for data in (b'', b'x' * (256 * 1024 + 1), b'10001-12000 rw-p 0 0 0\n',
                     b'10000-12000 rw-p 0 0 0\n11000-13000 rw-p 0 0 0\n'):
            with self.assertRaises(IsolationUnavailable):
                parse_maps(data)

    def test_auxiliary_missing_duplicate_or_unbounded_is_rejected(self):
        for maps in ((), (Mapping(0x10000, 0x20000, 'r-xp', '[vdso]'),) * 2,
                     (Mapping(0x10000, 0x200000, 'r-xp', '[vdso]'),)):
            with self.assertRaises(IsolationUnavailable):
                auxiliary_sizes(maps)

    def maps(self, *other):
        return (Mapping(0x10000, 0x12000, 'r-xp', '/xray'),
                Mapping(0x7FFFE000, 0x80000000, 'rw-p', '[stack]'),
                Mapping(0x80002000, 0x80004000, 'r-xp', '[vdso]'), *other)

    def test_exec_verification_returns_full_growable_stack_range(self):
        layout = InitialMemory(((0x10000, 0x12000),), (('[vdso]', 8192),))
        self.assertEqual(layout.verify_exec(self.maps()), (0x80000000 - STACK_LIMIT, 0x80000000))

    def test_exec_rejects_unaccounted_mapping_or_changed_kernel_images(self):
        layout = InitialMemory(((0x10000, 0x12000),), (('[vdso]', 8192),))
        for extra in (Mapping(0x90000000, 0x90001000, 'rw-p', ''),
                      Mapping(0x90000000, 0x90001000, 'r--p', '[vvar]')):
            with self.assertRaises(IsolationUnavailable):
                layout.verify_exec(self.maps(extra))

    def test_exec_rejects_oversized_or_duplicate_stack(self):
        layout = InitialMemory(((0x10000, 0x12000),), (('[vdso]', 8192),))
        for maps in (self.maps(Mapping(0x90000000, 0x90001000, 'rw-p', '[stack]')),
                     (self.maps()[0], Mapping(0x70000000, 0x80000000, 'rw-p', '[stack]'), self.maps()[2])):
            with self.assertRaises(IsolationUnavailable):
                layout.verify_exec(maps)

    def test_start_brk_is_read_after_last_parenthesis_and_pid_checked(self):
        fields = [b'S'] + [b'0'] * 43 + [b'268435456']
        data = b'123 (synthetic ) name) ' + b' '.join(fields)
        self.assertEqual(initial_break(data, 123), 0x10000000)
        with self.assertRaises(IsolationUnavailable):
            initial_break(data, 124)
        for invalid in (b'123 (x) S 0', data.replace(b'268435456', b'268435457')):
            with self.assertRaises(IsolationUnavailable):
                initial_break(invalid, 123)


if __name__ == '__main__':
    unittest.main()
