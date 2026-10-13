"""Конечный сценарий создания копии; планировщик и CLI вызывают один порт."""

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol


class BackupError(Exception):
    """Отказ с безопасным фиксированным сообщением без содержимого файлов."""


@dataclass(frozen=True)
class BackupResult:
    """Опубликованный проверенный архив и результат ограничения хранения."""

    name: str
    sha256: str
    size: int
    retained: int


class BackupStorage(Protocol):
    """Файловые операции одной транзакции; session удерживает общую блокировку."""

    def session(self) -> AbstractContextManager: ...
    def prepare(self) -> None: ...
    def create_and_verify(self) -> None: ...
    def publish(self) -> None: ...
    def retain(self) -> BackupResult: ...


def create_backup(storage: BackupStorage) -> BackupResult:
    """Не удалять старые копии до успешной проверки и публикации новой."""
    with storage.session():
        storage.prepare()
        storage.create_and_verify()
        storage.publish()
        return storage.retain()
