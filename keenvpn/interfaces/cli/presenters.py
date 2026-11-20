"""Совместимые имена представлений CLI для существующих вызывающих модулей."""

from keenvpn.application.keenetic_devices import ASSIGNMENT_LABELS
from keenvpn.interfaces.cli.presentation import (
    HIDDEN, Lines, MAX_TEXT_LENGTH, MISSING, Presenter, SNAPSHOT_NOTE, catalog_label as _catalog, check_line as _check_line,
    check_status, count, digest, file_name, flag, geo_source, geo_version, identifier, identifiers,
    interface_id, known_value, optional_count, optional_digest, optional_file_name, optional_flag,
    optional_identifier, present_error, present_result, safe_text,
)
from keenvpn.interfaces.cli.sections.connections import (
    CONNECTIONS_HEALTH_NOTE, CONNECTIONS_ITEM_NAME, CONNECTIONS_LIST_TITLE, CONNECTIONS_NOTE,
    SELECTORS_PER_LINE, present_connections,
)
from keenvpn.interfaces.cli.sections.devices import (
    DEVICES_ITEM_NAME, DEVICES_LIST_TITLE, DEVICES_NOTE, POLICY_IDS_PER_LINE, SEGMENT_MATCH_NOTE,
    device_name, present_device_list, present_keenetic_state,
)
from keenvpn.interfaces.cli.sections.draft import (
    DRAFT_KEPT, DRAFT_KEPT_IF_PRESENT, DRAFT_NOT_CHECKED, DRAFT_NOT_CONNECTED, created_at,
    present_menu_exit,
)
from keenvpn.interfaces.cli.sections.failsafe import DNS_PRITUNL_NOTE, PORT_53_NOTE, present_port53
from keenvpn.interfaces.cli.sections.routing import (
    API_SERVICE_NOTE, MAX_RULE_NAME_LENGTH, METADATA_NOTES, NAMES_PER_LABEL, OUTBOUND_TAGS_PER_LINE,
    POLICY_ABSENT_NOTE, ROUTE_NOTE, ROUTE_PROMPT, ROUTING_ITEM_NAME, ROUTING_LIST_TITLE,
    TARGET_POSITION_LABELS, UNKNOWN_ROUTE_NOTE, present_route_explanation, present_routing_scheme,
    present_rule_list, rule_id, rule_name,
)
from keenvpn.interfaces.cli.sections.settings import present_about, present_manager_metadata
from keenvpn.interfaces.cli.sections.status import (
    present_checks, present_geodata, present_installation, present_proxy_summary, present_quick_check,
    present_status_header, present_status_summary, present_xray_process,
)
