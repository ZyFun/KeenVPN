"""Хранилища, версия и справка меню."""

from keenvpn.application.contract import CONTRACT_VERSION, OperationIdFactory
from keenvpn.application.manager_metadata import (
    InspectManagerMetadata, InspectManagerMetadataHandler, ManagerMetadataStatusView,
)
from keenvpn.interfaces.cli.bindings import MenuSources, SectionActions
from keenvpn.interfaces.cli.menu import UnavailableReason
from keenvpn.interfaces.cli.presentation import (
    INDENT, count, identifier, Lines, optional_count, optional_flag, optional_identifier, present_result,
    ReportLayout,
)
from keenvpn.interfaces.cli.terminal import UNAVAILABLE_MARK


ACTION_CAPTIONS = {
    "settings.storage": "Сохранённые сведения о размещении данных и лимитах истории.",
    "settings.about": "Управление меню и версия контракта результатов.",
}


def present_manager_metadata(view: ManagerMetadataStatusView) -> Lines:
    """Показать метаданные менеджера без путей, идентификаторов хранилищ и ревизии."""
    if type(view) is not ManagerMetadataStatusView:
        raise TypeError("Ожидается ManagerMetadataStatusView.")
    lines = ["Метаданные менеджера"]
    if view.present is not True or view.metadata is None:
        lines.append("Метаданных нет: размещение хранилищ ещё не записано.")
        return lines
    metadata = view.metadata
    lines.append(
        f"Версия схемы: {count(metadata.schema_version)}; неизвестных полей: {count(metadata.unknown_field_count)}"
    )
    storage = metadata.storage
    if storage is None:
        lines.append("Размещение хранилищ не записано.")
        return lines
    lines.append(
        f"Вариант хранения: {identifier(storage.variant_state)} {optional_identifier(storage.variant)}; "
        f"различных хранилищ: {count(storage.distinct_storage_count)}"
    )
    for role in storage.roles:
        lines.append(
            f"{INDENT}Роль {identifier(role.role)}: состояние {identifier(role.state)}, "
            f"идентификатор {optional_identifier(role.storage_id_state)}, путь {optional_identifier(role.path_state)}, "
            f"проверено {optional_flag(role.verified)}"
        )
    limits = storage.history_limits
    lines.append(
        f"История: размер {identifier(limits.size_state)} {optional_count(limits.size_bytes)} байт; "
        f"срок {identifier(limits.retention_state)} {optional_count(limits.retention_seconds)} с"
    )
    return lines


def present_about() -> Lines:
    """Справка по навигации и версия контракта результатов."""
    return [
        "Справка по меню KeenVPN",
        "Выберите пункт, введя его номер и Enter. 0 возвращает на уровень выше, в корневом меню — завершает работу.",
        f"Пункты с пометкой {UNAVAILABLE_MARK} не выполняются: при выборе показывается причина, настройки не меняются.",
        "В списках номер открывает карточку элемента, другой текст ищет по показанным строкам, 0 возвращает назад.",
        "Отмена черновика доступна при подключённом порте удаления. Меню не меняет конфигурацию роутера, Xray и XKeen.",
        f"Версия контракта результатов прикладных сценариев: {CONTRACT_VERSION}",
    ]


def storage_layout(body: tuple[str, ...]) -> ReportLayout:
    roles = tuple(line for line in body if line.startswith("  Роль "))
    summary = tuple(line for line in body if not line.startswith("  Роль "))
    return summary, (("Роли хранилищ", roles),) if roles else ()


def help_layout(body: tuple[str, ...]) -> ReportLayout:
    summary = []
    for line in body:
        if line == ("Выберите пункт, введя его номер и Enter. 0 возвращает на уровень выше, "
                    "в корневом меню — завершает работу."):
            summary.extend(("Выбор: ↑/↓ и Enter или номер и Enter.",
                            "Назад: Esc или 0 и Enter. В главном меню эти клавиши открывают выход.",
                            "Главное меню: Home."))
        elif line.startswith("Пункты с пометкой [недоступно]"):
            summary.append("Закрытые пункты: в скобках указана причина. Ввод номера показывает её.")
        elif line == ("В списках номер открывает карточку элемента, другой текст ищет по показанным строкам, "
                      "0 возвращает назад."):
            summary.extend(("Карточка: Enter на выбранной строке.", "Поиск: /, текст и Enter.",
                            "Подробности: Tab меняет вид списка, карточки или отчёта.",
                            "Источник: i в списке подключений, правил или устройств.",
                            "Прокрутка: ↑/↓ или PgUp/PgDn."))
        else:
            summary.append(line)
    return tuple(summary), ()


def bind_actions(bindings: SectionActions, sources: MenuSources, operation_ids: OperationIdFactory) -> None:
    """Подключить справку и показ размещения собственных данных менеджера."""
    bindings["settings.about"] = present_about
    if sources.metadata is not None:
        metadata = InspectManagerMetadataHandler(sources.metadata, operation_ids=operation_ids)
        bindings["settings.storage"] = lambda: present_result(metadata.execute(InspectManagerMetadata()), present_manager_metadata)
    elif sources.storage_error is not None:
        bindings["settings.storage"] = UnavailableReason.STORAGE_NOT_CONFIRMED
