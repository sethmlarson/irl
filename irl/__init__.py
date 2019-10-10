"""URLs for IRL"""

import enum
import typing
import sys
from .parser import parse_url


__version__ = "0.2"
__all__ = ["parse_url", "ParsePolicy", "IS_INTERACTIVE_MODE", "URLError"]

# sys.ps1 only exists in interactive mode.
IS_INTERACTIVE_MODE = hasattr(sys, "ps1")

# Default ports by scheme
SCHEME_DEFAULT_PORTS = {
    "ftp": 21,
    "gopher": 70,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "ssh": 22,
}
SPECIAL_SCHEMES = {"ftp", "file", "gopher", "http", "https", "ws", "wss"}

# Character Sets
SINGLE_DOT_PATH_SEGMENT = {".", "%2e"}
DOUBLE_DOT_PATH_SEGMENT = {"..", ".%2e", "%2e.", "%2e%2e"}
C0_CONTROL_SET = set([chr(x) for x in range(0x00, 0x20)])
FRAGMENT_SET = C0_CONTROL_SET | {" ", '"', "<", ">", "`"}
PATH_SET = FRAGMENT_SET | {"#", "?", "{", "}"}
USERINFO_SET = PATH_SET | {"/", ":", ";", "=", "@", "[", "\\", "]", "^", "|"}


class ParsePolicy(enum.Enum):
    HAND_TYPED = "HAND_TYPED"
    LAX = "LAX"
    STRICT = "STRICT"


class URLError(Exception):
    pass
