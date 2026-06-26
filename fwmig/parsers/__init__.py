from .cisco_asa   import CiscoASAParser
from .cisco_fwsm  import CiscoFWSMParser
from .cisco_ftd   import CiscoFTDParser
from .palo_alto   import PaloAltoParser
from .fortigate   import FortiGateParser
from ..models     import Platform

PARSER_MAP = {
    Platform.CISCO_ASA:  CiscoASAParser,
    Platform.CISCO_FWSM: CiscoFWSMParser,
    Platform.CISCO_FTD:  CiscoFTDParser,
    Platform.PALO_ALTO:  PaloAltoParser,
    Platform.FORTIGATE:  FortiGateParser,
}


def get_parser(platform: Platform, version: str):
    cls = PARSER_MAP[platform]
    return cls(version)
