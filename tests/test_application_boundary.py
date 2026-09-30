"""Граница прикладных сценариев: зависимости, терминал и представление результата."""

import ast
import getpass
from importlib.util import resolve_name
import json
import os
from pathlib import Path
import shutil
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from keenvpn.adapters.trojan_uri import TrojanLinkParser
from keenvpn.application.connections import InspectConnectionLink, InspectConnectionLinkHandler
from keenvpn.application.contract import CONTRACT_VERSION, OperationStatus, Result
from keenvpn.application.routing import ExplainRoute, ExplainRouteHandler
from keenvpn.domain.connection import SecretValue
from keenvpn.domain.routing import GeoDatabase, GeoDatabaseKind, GeoIPCondition, RoutingAction, RoutingRule
from keenvpn.domain.routing_explanation import GeoMatch, IPSource
from keenvpn.domain.routing_policy import FinalRoutingRule, MatchResult, RoutingPolicy
from tests.support.in_memory import InMemoryGeoDataSource, InMemoryRoutingPolicySource
from tests.support.isolation import forbid_external_effects


# Эти модули отвечают за диалог, аргументы процесса и отображение, а не модели.
PRESENTATION_MODULES = frozenset({
    "argparse", "cmd", "getpass", "readline", "curses", "termios", "tty", "sys",
    "click", "typer", "rich", "textual", "prompt_toolkit", "colorama",
    "tabulate", "prettytable", "pprint", "textwrap",
})


# Загрузка кода и модулей в обход обычного импорта.
DYNAMIC_BUILTINS = frozenset({"__import__", "exec", "eval", "compile"})
DYNAMIC_MODULES = frozenset({"importlib", "pkgutil", "runpy"})
# Прямой ввод-вывод в обход print/input: дескрипторы и открытие /dev/tty.
RAW_IO = frozenset({"os.read", "os.write", "os.open", "builtins.open", "io.open"})


def boundary_violations(source: str, module: str, *, package: bool = False) -> list[str]:
    """Проверить обычные импорты, терминальные builtins и ANSI в исходнике.

    Проверка не исполняет код и не пытается анализировать произвольную динамику.
    Динамическая загрузка модулей внутри domain/application/adapters также
    запрещена. Прямой ввод-вывод запрещён только domain/application: адаптерам
    файлы и дескрипторы понадобятся для работы с роутером.
    """
    tree = ast.parse(source)
    allowed = ("keenvpn.domain",)
    raw_io = RAW_IO
    if module.startswith("keenvpn.application"):
        allowed += ("keenvpn.application",)
    elif module.startswith("keenvpn.adapters"):
        allowed += ("keenvpn.application", "keenvpn.adapters")
        raw_io = frozenset()
    builtins = {"input", "print", *DYNAMIC_BUILTINS} | ({"open"} if raw_io else set())
    # `compile` и `open` как атрибуты не проверяются: иначе `re.compile` и
    # методы моделей считались бы нарушением. `os.open` ловится через raw_io.
    attributes = builtins - {"compile", "open"}
    aliases = {
        alias.asname: alias.name
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names if alias.asname
    }
    violations = []
    for node in ast.walk(tree):
        imports = []
        if isinstance(node, ast.Import):
            imports = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = module if package else module.rpartition(".")[0]
                base = resolve_name("." * node.level + base, parent)
            # Учитываем и `from keenvpn import adapters`, и алиасы имён.
            imports = [base, *(base + "." + alias.name for alias in node.names)]
        for name in imports:
            root = name.split(".")[0]
            if root == "keenvpn" and name != "keenvpn":
                if not any(name == prefix or name.startswith(prefix + ".") for prefix in allowed):
                    violations.append(f"{node.lineno}: зависимость от {name}")
            elif root in PRESENTATION_MODULES or root == "tests" or root in DYNAMIC_MODULES:
                violations.append(f"{node.lineno}: зависимость от {name}")
            elif name in raw_io or name in {f"builtins.{builtin}" for builtin in builtins}:
                violations.append(f"{node.lineno}: терминальный, динамический или прямой вызов {name}")
        if isinstance(node, ast.Name) and node.id in builtins:
            violations.append(f"{node.lineno}: builtin {node.id}")
        if isinstance(node, ast.Attribute):
            owner = aliases.get(node.value.id, node.value.id) if isinstance(node.value, ast.Name) else None
            if node.attr in attributes or f"{owner}.{node.attr}" in raw_io:
                violations.append(f"{node.lineno}: терминальный, динамический или прямой атрибут {node.attr}")
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            escapes = ("\x1b", "\x9b") if isinstance(node.value, str) else (b"\x1b", b"\x9b")
            if any(escape in node.value for escape in escapes):
                violations.append(f"{node.lineno}: управляющая последовательность терминала")
    return violations


class ApplicationDependencyTests(unittest.TestCase):
    def test_application_and_domain_keep_dependency_direction(self):
        # Domain и adapters проверяются вместе с application: иначе UI можно
        # внести транзитивно через доменную модель или адаптер за портом.
        paths = [ROOT / "keenvpn/__init__.py"]
        for layer in ("application", "domain", "adapters"):
            modules = sorted((ROOT / "keenvpn" / layer).rglob("*.py"))
            self.assertTrue(modules)
            paths.extend(modules)
        for path in paths:
            parts = path.relative_to(ROOT).with_suffix("").parts
            package = parts[-1] == "__init__"
            module = ".".join(parts[:-1] if package else parts)
            with self.subTest(module=module):
                self.assertEqual(boundary_violations(path.read_text(), module, package=package), [])

    def test_dependency_check_rejects_interface_and_adapter_imports(self):
        for source in (
            "import keenvpn.adapters.trojan_uri as parser",
            "from keenvpn import adapters as sources",
            "from ..adapters import trojan_uri",
            "from .. import interfaces",
            "from keenvpn.interfaces.cli import render",
            "from tests.support.in_memory import InMemoryRoutingPolicySource",
            "def run():\n    from getpass import getpass as read_secret",
            "if TYPE_CHECKING:\n    import rich.console",
            "import sys as process",
            "from builtins import input as read_answer",
            "from builtins import print as render",
            "read_answer = input",
            "import builtins as b\nb.print('текст')",
            "__import__('keenvpn.interfaces.cli')",
            "import importlib as loader",
            "text = '\\x1b[32mГотово\\x1b[0m'",
            "exec('import keenvpn.interfaces')",
            "eval('1')",
            "compile('1', 'x', 'eval')",
            "import pkgutil\npkgutil.resolve_name('keenvpn.interfaces.cli')",
            "import runpy",
            "import os\nos.write(1, b'x')",
            "import os as system\nsystem.read(0, 1)",
            "from os import write",
            "open('/dev/tty', 'w')",
            "data = b'\\x1b[31m'",
        ):
            with self.subTest(source=source):
                self.assertTrue(boundary_violations(source, "keenvpn.application.example"))
        self.assertTrue(boundary_violations(
            "from ..application import contract", "keenvpn.domain.example",
        ))
        for source in (
            "from ..interfaces import cli",
            "import rich",
            "print('текст')",
            "import pkgutil",
            "text = '\\x1b[31m'",
        ):
            with self.subTest(adapter=source):
                self.assertTrue(boundary_violations(source, "keenvpn.adapters.example"))

    def test_dependency_check_allows_ports_models_and_safe_messages(self):
        source = (
            "from dataclasses import dataclass\n"
            "from ..domain.connection import SecretValue\n"
            "from .ports import ConnectionLinkParser\n"
            "message = f'Поддерживается версия {version}.'\n"
            "def to_dict():\n    return {'message': message}\n"
        )
        self.assertEqual(boundary_violations(source, "keenvpn.application.example"), [])
        self.assertEqual(boundary_violations(
            "from .connections import InspectConnectionLink",
            "keenvpn.application", package=True,
        ), [])
        # Адаптер реализует порт application и может читать файлы роутера.
        self.assertEqual(boundary_violations(
            "import re\nfrom ..application.ports import ConnectionLinkParser\n"
            "PATTERN = re.compile('x')\nwith open('config.json') as source:\n    pass\n",
            "keenvpn.adapters.example",
        ), [])


class CountingTrojanLinkParser(TrojanLinkParser):
    """Настоящий парсер со счётчиком обращений для проверки представления."""

    def __init__(self) -> None:
        self.calls = 0

    def parse(self, link: str):
        self.calls += 1
        return super().parse(link)


class ApplicationPresentationTests(unittest.TestCase):
    def assert_presentable(self, result, calls):
        """Два независимых потребителя не вызывают сценарий или его порты."""
        self.assertIsInstance(result, Result)
        before = calls()
        with forbid_external_effects():
            data = result.to_dict()
            encoded = json.dumps(data, ensure_ascii=False)
            # Тестовый потребитель выбирает текст по структуре, а не разбирает
            # message. Это не реализация CLI и не отдельный прикладной сценарий.
            if result.succeeded:
                fields = "; ".join(f"{key}={value}" for key, value in result.data.to_dict().items())
                text = f"{result.command}: {fields}"
            else:
                text = f"{result.error.category.value}: {result.error.code}"
            self.assertEqual(result.to_dict(), data)
        self.assertEqual(json.loads(encoded), data)
        self.assertIsInstance(text, str)
        self.assertEqual(calls(), before)
        for private in ("TEST_ONLY_PASSWORD", "vpn.example.test", "192.0.2.10", "fixture-ip"):
            self.assertNotIn(private, encoded + text + repr(result))
        self.assertNotIn("\x1b", encoded + text)

    def test_link_success_and_rejections_need_no_terminal(self):
        link = "trojan://TEST_ONLY_PASSWORD@vpn.example.test:443?security=tls&type=ws"
        parser = CountingTrojanLinkParser()
        handler = InspectConnectionLinkHandler(parser)
        for command, status, code in (
            (InspectConnectionLink(SecretValue(link)), OperationStatus.SUCCEEDED, None),
            (InspectConnectionLink(SecretValue(link.replace(":443", ":0"))),
             OperationStatus.FAILED, "invalid_uri"),
            (InspectConnectionLink(SecretValue(link.replace("ws", "grpc"))),
             OperationStatus.FAILED, "unsupported_uri"),
            (InspectConnectionLink(SecretValue(link), contract_version=CONTRACT_VERSION + 1),
             OperationStatus.FAILED, "unsupported_contract_version"),
            (link, OperationStatus.FAILED, "invalid_command"),
        ):
            with self.subTest(code=code), forbid_external_effects():
                result = handler.execute(command)
                self.assertIs(result.status, status)
                self.assertEqual(None if result.error is None else result.error.code, code)
            self.assert_presentable(result, lambda: parser.calls)

    def test_route_success_unknown_and_failure_need_no_terminal(self):
        database = GeoDatabase(GeoDatabaseKind.GEOIP, "fixture-ip")
        condition = GeoIPCondition(database, "test-set")
        policy = RoutingPolicy(
            (RoutingRule(condition, RoutingAction.VPN),), FinalRoutingRule(RoutingAction.DIRECT),
        )
        policies = InMemoryRoutingPolicySource(policy)
        geodata = InMemoryGeoDataSource()
        handler = ExplainRouteHandler(policies, geodata)
        command = ExplainRoute(ips=("192.0.2.10",), ip_source=IPSource.DNS)
        for outcome, status, action in (
            (GeoMatch(MatchResult.MATCH, database), OperationStatus.SUCCEEDED, "VPN"),
            (GeoMatch(MatchResult.UNKNOWN, database), OperationStatus.SUCCEEDED, None),
            (OSError("Отказ для 192.0.2.10"), OperationStatus.FAILED, None),
        ):
            geodata.set_response(condition, command.ips, outcome)
            with self.subTest(status=status, action=action), forbid_external_effects():
                result = handler.execute(command)
                self.assertIs(result.status, status)
                if result.succeeded:
                    selection = result.data.selection
                    self.assertEqual(None if selection is None else selection.action, action)
                else:
                    self.assertEqual(result.error.code, "rule_matcher_failed")
                    self.assertIsNone(result.data)
            self.assert_presentable(result, lambda: (policies.calls, geodata.calls))


class TerminalIsolationTests(unittest.TestCase):
    def test_swallowed_stdin_read_is_still_reported(self):
        for name, read in (
            ("read", lambda: sys.stdin.read()),
            ("readline", lambda: sys.stdin.readline()),
            ("readlines", lambda: sys.stdin.readlines()),
            ("iteration", lambda: next(iter(sys.stdin))),
            ("buffer", lambda: sys.stdin.buffer.read()),
            ("original", lambda: sys.__stdin__.read()),
        ):
            with self.subTest(method=name), self.assertRaises(AssertionError):
                with forbid_external_effects():
                    try:
                        read()
                    except AssertionError:
                        pass

    def test_terminal_helpers_and_raw_descriptors_are_blocked(self):
        for name, effect in (
            ("getpass", lambda: getpass.getpass("Искусственный запрос: ")),
            ("terminal_size", lambda: os.get_terminal_size()),
            ("size_with_fallback", lambda: shutil.get_terminal_size()),
            ("read_fd", lambda: os.read(0, 1)),
            ("write_fd", lambda: os.write(1, b"test")),
            ("original_stdout", lambda: sys.__stdout__.write("вывод")),
            ("original_stderr", lambda: sys.__stderr__.write("вывод")),
            ("stdin_isatty", lambda: sys.stdin.isatty()),
            ("stdout_isatty", lambda: sys.stdout.isatty()),
            ("stderr_isatty", lambda: sys.stderr.isatty()),
            ("original_stdout_isatty", lambda: sys.__stdout__.isatty()),
            ("isatty_fd", lambda: os.isatty(1)),
        ):
            with self.subTest(effect=name), self.assertRaises(AssertionError):
                with forbid_external_effects():
                    try:
                        effect()
                    except AssertionError:
                        pass

    def test_stdin_violation_survives_later_scenario_exception(self):
        with self.assertRaises(AssertionError) as caught:
            with forbid_external_effects():
                try:
                    sys.stdin.read()
                except AssertionError:
                    pass
                raise ValueError("Ожидаемый отказ сценария.")
        self.assertIsInstance(caught.exception.__context__, ValueError)

    def test_streams_and_helpers_are_restored_after_failure(self):
        streams = (sys.stdin, sys.stdout, sys.stderr, sys.__stdin__, sys.__stdout__, sys.__stderr__)
        read_secret = getpass.getpass
        with self.assertRaises(AssertionError):
            with forbid_external_effects():
                getpass.getpass()
        self.assertEqual(
            (sys.stdin, sys.stdout, sys.stderr, sys.__stdin__, sys.__stdout__, sys.__stderr__), streams,
        )
        self.assertIs(getpass.getpass, read_secret)


if __name__ == "__main__":
    unittest.main()
