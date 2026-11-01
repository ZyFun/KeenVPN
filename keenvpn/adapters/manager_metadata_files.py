"""Файловое хранилище собственных метаданных менеджера в явно заданном каталоге.

Каталог задаёт вызывающий код: значение по умолчанию не выбирается, а при
недоступности не используются другой каталог, `/opt` или RAM. Механика
приватного файла — общая с хранилищем черновика (`private_files`): права
700/600, обход без ссылок, атомарная запись по ожидаемой ревизии под
эксклюзивной блокировкой каталога, запрет каталогов конфигураций Xray
и XKeen и каталога init. Этот модуль задаёт имя и формат файла и коды
отказов порта `ManagerMetadataStore`.
"""

from keenvpn.adapters.private_files import PrivateFileStore, StoreFailure
from keenvpn.application.ports import ManagerMetadataStoreError, MetadataStoreFailure
from keenvpn.domain.manager_metadata import (
    MAX_METADATA_SIZE, ManagerMetadata, ManagerMetadataError, StoredManagerMetadata,
    decode_manager_metadata, encode_manager_metadata, metadata_revision,
)


METADATA_FILE_NAME = "manager-metadata.json"
"""Имя файла метаданных в собственном каталоге."""


class ManagerMetadataFiles(PrivateFileStore[StoredManagerMetadata]):
    """Реализация `ManagerMetadataStore` на файловой системе.

    `directory` — абсолютный нормализованный путь собственного каталога
    метаданных без символических ссылок, например на выбранном разделе.
    Каталог, совпадающий с одним из `protected_directories` или вложенный
    в него, отклоняется до любого обращения к файловой системе.
    """

    file_name = METADATA_FILE_NAME
    max_size = MAX_METADATA_SIZE
    error_type = ManagerMetadataStoreError
    failures = {failure: MetadataStoreFailure[failure.name] for failure in StoreFailure}
    revision_of = staticmethod(metadata_revision)

    def read_metadata(self) -> StoredManagerMetadata | None:
        """Прочитать файл без блокировки: запись публикует его одним переименованием.

        `None` — собственного каталога или файла ещё нет; отсутствие родителя
        является отказом `metadata_store_unavailable`.
        """
        return self._read_file()

    def write_metadata(self, metadata: ManagerMetadata, expected_revision: str | None) -> str:
        """Записать при совпадении ревизии и вернуть новую.

        Модель проверяется до обращения к файловой системе: некорректная
        вызывает `ManagerMetadataError`. Повреждённый файл и файл другой
        версии схемы не перезаписываются. Совпадающие байты не записываются
        повторно, но файл и каталог закрепляются fsync.
        """
        return self._write_file(encode_manager_metadata(metadata), expected_revision)

    def _decode(self, content: bytes) -> StoredManagerMetadata:
        code = None
        try:
            return decode_manager_metadata(content)
        except ManagerMetadataError as error:
            code = error.code
        self._raise(StoreFailure.INVALID, code.value)
