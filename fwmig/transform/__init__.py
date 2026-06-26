from .interface_map import (
    collect_interface_names,
    suggest_target_names,
    apply_interface_mapping,
    source_key,
    IfaceIdentity,
)
from .service_normalize import normalize_service_groups, normalize_inline_services
from .network_normalize import materialize_address_literals

__all__ = [
    "collect_interface_names",
    "suggest_target_names",
    "apply_interface_mapping",
    "source_key",
    "IfaceIdentity",
    "normalize_service_groups",
    "normalize_inline_services",
    "materialize_address_literals",
]
