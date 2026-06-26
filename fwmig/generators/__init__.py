from .cisco_asa  import CiscoASAGenerator
from .cisco_fwsm import CiscoFWSMGenerator
from .cisco_ftd  import CiscoFTDGenerator
from .palo_alto  import PaloAltoGenerator
from .fortigate  import FortiGateGenerator
from ..models    import Platform

GENERATOR_MAP = {
    Platform.CISCO_ASA:  CiscoASAGenerator,
    Platform.CISCO_FWSM: CiscoFWSMGenerator,
    Platform.CISCO_FTD:  CiscoFTDGenerator,
    Platform.PALO_ALTO:  PaloAltoGenerator,
    Platform.FORTIGATE:  FortiGateGenerator,
}


def get_generator(platform: Platform, version: str):
    cls = GENERATOR_MAP[platform]
    return cls(version)
