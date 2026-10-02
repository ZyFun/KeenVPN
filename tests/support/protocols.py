"""Искусственный протокол для контрактных тестов расширения реестра."""

from dataclasses import dataclass, replace

from keenvpn.application.protocol_registry import ProtocolField, ProtocolModule
from keenvpn.domain.connection import SecretValue


@dataclass(frozen=True, repr=False)
class SampleParameters:
    """Искусственная модель для проверки расширения, не VPN-протокол."""

    value: SecretValue
    protocol: str = "sample"


def sample_module(**changes):
    """Независимая регистрация без изменения алгоритма выбора."""
    module = ProtocolModule(
        "sample", ("sample", "sample+alias"), SampleParameters,
        (ProtocolField("value", secret=True, required=True),),
        parse_uri=lambda uri: SampleParameters(SecretValue(uri)),
        validate_parameters=lambda parameters: None,
    )
    return replace(module, **changes)
