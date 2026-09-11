"""Регрессии офлайн-аудита; только искусственные IPK, без сети и роутера."""

import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "audit_entware", Path(__file__).resolve().parents[1] / "scripts" / "audit_entware.py",
)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def tar_bytes(entries, compressed=True):
    """Собрать маленький архив для проверки чтения и расчёта размеров."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz" if compressed else "w:") as archive:
        for name, content in entries:
            member = tarfile.TarInfo(name)
            if content is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


def package(entries):
    """Создать IPK с содержимым и согласованной записью каталога."""
    data = tar_bytes([("./data.tar.gz", tar_bytes(entries))])
    return data, {"Size": str(len(data)), "SHA256sum": hashlib.sha256(data).hexdigest()}


class DependencyTests(unittest.TestCase):
    def test_realistic_package_names_and_duplicate_rejection(self):
        """Регистр и подчёркивания допустимы, неоднозначная запись пакета — нет."""
        data = b"Package: cJSON\nVersion: 1\n\nPackage: boost-date_time\nVersion: 2\n"
        self.assertEqual(set(audit.parse_index(data)), {"cJSON", "boost-date_time"})
        with self.assertRaises(audit.AuditError):
            audit.parse_index(data + b"\nPackage: cJSON\nVersion: 3\n")
        with self.assertRaises(audit.AuditError):
            audit.parse_index(b"Package: sample\nSize: 1\nSize: 2\n")

    def test_shared_dependency_is_counted_once_and_provider_is_explicit(self):
        """Общая библиотека не удваивается, виртуальный пакет разрешается явно."""
        records = {
            "app": {"Depends": "one, two, ca-certs"},
            "one": {"Depends": "shared"}, "two": {"Depends": "shared"}, "shared": {},
            "bundle": {"Provides": "ca-certs"},
        }
        result = audit.dependency_closure(records, ("app",), {"ca-certs": "bundle"})
        self.assertEqual(set(result), set(records))
        with self.assertRaises(audit.AuditError):
            audit.dependency_closure(records, ("app",), {})
        records["bundle"] = {}
        with self.assertRaises(audit.AuditError):
            audit.dependency_closure(records, ("app",), {"ca-certs": "bundle"})

    def test_unknown_dependency_syntax_is_not_silently_simplified(self):
        """Ограничения версии и альтернативы требуют другого решателя зависимостей."""
        for dependency in ("missing", "lib (>= 2)", "one | two"):
            with self.subTest(dependency=dependency), self.assertRaises(audit.AuditError):
                audit.dependency_closure({"app": {"Depends": dependency}, "lib": {}}, ("app",), {})

    def test_mixed_python_builds_stop_before_reading_archives(self):
        """Смешанный набор Python не проходит аудит даже при правильных именах пакетов."""
        selected = {
            'python3-light': {'Version': '3.13.9-2'},
            'python3-openssl': {'Version': '3.12.14-1'},
        }
        with (
            patch.object(audit, 'dependency_closure', return_value=selected),
            patch.object(audit, 'read_limited') as reader,
            self.assertRaises(audit.AuditError),
        ):
            audit.audit(b'Package: sample\n', 'unused', ('ssl',))
        reader.assert_not_called()


class ArchiveTests(unittest.TestCase):
    def test_archive_sizes_include_tar_and_block_rounding_without_extract(self):
        """Сжатый архив, логический размер и оценка блоков — разные величины."""
        data, record = package([("./opt", None), ("./opt/a", b"x"), ("./opt/b", b"y" * 4097)])
        with patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("Запрещено")):
            files, sizes = audit.inspect_ipk(data, record)
        self.assertEqual(files["opt/a"], b"x")
        self.assertEqual(sizes["regular_file_bytes"], 4098)
        self.assertEqual(sizes["estimated_4k_bytes"], 4096 + 4096 + 8192)
        self.assertGreater(sizes["payload_tar_bytes"], sizes["regular_file_bytes"])

    def test_checksum_and_size_mismatch_stop_before_archive_parsing(self):
        """Повреждённый IPK не анализируется даже при доступных метаданных."""
        data, record = package([("opt/a", b"sample")])
        for changed in ({**record, "Size": "0"}, {**record, "SHA256sum": "0" * 64}):
            with self.subTest(record=changed), patch.object(tarfile, "open") as opened:
                with self.assertRaises(audit.AuditError):
                    audit.inspect_ipk(data, changed)
                opened.assert_not_called()

    def test_unsafe_paths_duplicates_and_oversize_are_rejected(self):
        """Некорректное содержимое не превращается в успешный отчёт."""
        for entries in ([('../outside', b'x')], [('/outside', b'x')], [('opt/a', b'x'), ('./opt/a', b'y')]):
            data, record = package(entries)
            with self.subTest(entries=entries), self.assertRaises(audit.AuditError):
                audit.inspect_ipk(data, record)
        data, record = package([('opt/a', b'x' * 200)])
        with patch.object(audit, "MAX_TAR", 100), self.assertRaises(audit.AuditError):
            audit.inspect_ipk(data, record)

    def test_missing_payload_is_not_an_empty_success(self):
        data = tar_bytes([('control.tar.gz', b'not a payload')])
        record = {'Size': str(len(data)), 'SHA256sum': hashlib.sha256(data).hexdigest()}
        with self.assertRaises(audit.AuditError):
            audit.inspect_ipk(data, record)

    def test_missing_module_is_distinct_from_python_wrapper_without_extension(self):
        """ssl.pyc не доказывает наличие _ssl.so; необязательный пакет не угадывается."""
        files = {'light': {'opt/lib/python3.13/ssl.pyc': b'placeholder'}}
        self.assertEqual(audit.module_owners('ssl', files), ['light'])
        self.assertEqual(audit.module_owners('_ssl', files), [])
        self.assertEqual(audit.module_owners('logging', files), [])


class CertificateAndCommandTests(unittest.TestCase):
    def test_public_test_ca_loads_without_network_processes_or_keylog(self):
        """Искусственный открытый CA загружается офлайн; закрытого ключа в git нет."""
        certificate = Path(__file__).with_name('fixtures').joinpath('ca-test.crt').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / 'keys.log'
            with (
                patch.dict(os.environ, {'SSLKEYLOGFILE': str(keylog)}),
                patch.object(socket, 'socket', side_effect=AssertionError('Сеть запрещена')),
                patch.object(subprocess, 'Popen', side_effect=AssertionError('Процессы запрещены')),
                patch.object(ssl.SSLContext, 'load_default_certs', side_effect=AssertionError('Fallback запрещён')),
            ):
                self.assertEqual(audit.ca_count(certificate), 1)
            self.assertFalse(keylog.exists())

    def test_invalid_ca_does_not_fall_back_to_system_trust(self):
        """Пустой/испорченный PEM не подменяется доверенными сертификатами Mac."""
        with patch.object(ssl.SSLContext, 'load_default_certs', side_effect=AssertionError('Fallback запрещён')):
            for data in (b'', b'not a certificate'):
                with self.subTest(data=data), self.assertRaises((ValueError, ssl.SSLError)):
                    audit.ca_count(data)

    def test_ca_context_rejects_empty_store_and_disabled_verification(self):
        """Успешный вызов загрузки не равен непустому хранилищу CA с проверкой."""
        for count, hostname, mode in ((0, True, ssl.CERT_REQUIRED), (1, False, ssl.CERT_REQUIRED), (1, True, ssl.CERT_NONE)):
            with patch.object(ssl, 'SSLContext') as factory:
                context = factory.return_value
                context.cert_store_stats.return_value = {'x509_ca': count}
                context.check_hostname = hostname
                context.verify_mode = mode
                with self.assertRaises(audit.AuditError):
                    audit.ca_count(b'placeholder')

    def test_input_limit_and_error_output_do_not_expose_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'TEST_SECRET'
            path.write_bytes(b'too long')
            with self.assertRaises(audit.AuditError):
                audit.read_limited(path, 2)
            for args, code in ((['TEST_SECRET'], 2), ([str(path), 'TEST_SECRET'], 1)):
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    self.assertEqual(audit.main(args), code)
                self.assertNotIn('TEST_SECRET', output.getvalue())
                self.assertNotIn('Traceback', output.getvalue())


if __name__ == '__main__':
    unittest.main()
