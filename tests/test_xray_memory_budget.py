"""Проверки предварительного бюджета; эти тесты не подтверждают ограничения ядра."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keenvpn.adapters.xray_memory_budget import (
    MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MemoryBudgetExceeded,
    PROT_READ, PROT_WRITE, UnsupportedMemoryOperation, XrayMemoryBudget,
)


class XrayMemoryBudgetTests(unittest.TestCase):
    def test_initial_budget_is_reserved_before_first_operation(self):
        with self.assertRaises(MemoryBudgetExceeded):
            XrayMemoryBudget(4096, 4097)
        budget = XrayMemoryBudget(8192, 1)
        self.assertEqual(budget.used, 4096)

    def test_go_virtual_reservation_does_not_spend_resident_budget(self):
        budget = XrayMemoryBudget(256 * 1024 * 1024, 40 * 1024 * 1024)
        budget.before_mmap(0, 613548032, 0, MAP_PRIVATE | MAP_ANONYMOUS)
        self.assertEqual(budget.used, 40 * 1024 * 1024)
        budget.before_mmap(0x40000000, 4097, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED)
        self.assertEqual(budget.used, 40 * 1024 * 1024 + 8192)

    def test_downgrade_does_not_refund_resident_pages(self):
        budget = XrayMemoryBudget(8192, 0)
        budget.before_mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)
        budget.before_mprotect(0x40000000, 8192, 0)
        self.assertEqual(budget.used, 8192)
        with self.assertRaises(MemoryBudgetExceeded):
            budget.before_mmap(0, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)

    def test_replacement_and_failed_operations_cannot_refund_budget(self):
        budget = XrayMemoryBudget(8192, 0)
        budget.before_mmap(0x40000000, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED)
        # Даже если ядро вернуло ошибку или заменяет прежнее отображение, возврата нет.
        budget.before_mmap(0x40000000, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED)
        self.assertEqual(budget.used, 8192)
        with self.assertRaises(MemoryBudgetExceeded):
            budget.before_mprotect(0x40000000, 4096, PROT_READ)

    def test_full_protection_range_is_reserved_before_partial_effect(self):
        budget = XrayMemoryBudget(12288, 0)
        budget.before_mprotect(0x40000000, 8193, PROT_READ)
        self.assertEqual(budget.used, 12288)
        with self.assertRaises(MemoryBudgetExceeded):
            budget.before_mprotect(0x50000000, 4096, PROT_READ)

    def test_file_backed_readonly_pages_are_charged(self):
        budget = XrayMemoryBudget(8192, 0)
        budget.before_mmap(0, 4096, PROT_READ, MAP_PRIVATE)
        budget.before_mmap(0, 4096, 0, MAP_PRIVATE)
        self.assertEqual(budget.used, 8192)

    def test_populate_growsdown_shared_and_unknown_flags_are_rejected(self):
        for flag in (0x8000, 0x100, 1, 0x40000, 0x80000000):
            with self.subTest(flag=flag):
                budget = XrayMemoryBudget(8192, 0)
                with self.assertRaises(UnsupportedMemoryOperation):
                    budget.before_mmap(0, 4096, 0, MAP_PRIVATE | MAP_ANONYMOUS | flag)
                self.assertEqual(budget.used, 0)

    def test_shared_ledger_reserves_before_any_syscall_completion(self):
        budget = XrayMemoryBudget(8192, 0)
        budget.before_mmap(0, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)
        budget.before_mmap(0, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)
        with self.assertRaises(MemoryBudgetExceeded):
            budget.before_mmap(0, 4096, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)

    def test_brk_uses_maximum_without_refund_after_shrink(self):
        budget = XrayMemoryBudget(8192, 0)
        budget.set_initial_break(0x100001)
        budget.before_brk(0x101001)
        self.assertEqual(budget.used, 4096)
        budget.before_brk(0x100001)
        budget.before_brk(0x101001)
        self.assertEqual(budget.used, 4096)
        budget.before_brk(0x102001)
        self.assertEqual(budget.used, 8192)
        with self.assertRaises(MemoryBudgetExceeded):
            budget.before_brk(0x103001)

    def test_brk_requires_initial_origin_and_cannot_reset_it(self):
        budget = XrayMemoryBudget(8192, 0)
        budget.before_brk(0)
        with self.assertRaises(UnsupportedMemoryOperation):
            budget.before_brk(0x100000)
        budget.set_initial_break(0x100000)
        with self.assertRaises(UnsupportedMemoryOperation):
            budget.set_initial_break(0x200000)

    def test_invalid_native_arguments_are_rejected_without_charging(self):
        operations = [lambda b: b.before_mmap(0, True, PROT_READ, MAP_PRIVATE),
                      lambda b: b.before_mmap(0, -1, PROT_READ, MAP_PRIVATE),
                      lambda b: b.before_mmap((1 << 64) - 4096, 8192, PROT_READ, MAP_PRIVATE),
                      lambda b: b.before_mmap(1, 4096, PROT_READ, MAP_PRIVATE | MAP_FIXED),
                      lambda b: b.before_mprotect(1, 4096, PROT_READ),
                      lambda b: b.before_mprotect(0, 4096, 0x1000000)]
        for operation in operations:
            with self.subTest(operation=operation):
                budget = XrayMemoryBudget(8192, 0)
                with self.assertRaises(UnsupportedMemoryOperation):
                    operation(budget)
                self.assertEqual(budget.used, 0)


if __name__ == '__main__':
    unittest.main()
