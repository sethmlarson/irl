import enum
import re
import string
import typing
from .models import BaseURL


ASCII_DIGIT = set(string.digits)
ASCII_ALPHA = set(string.ascii_letters)
SCHEME = ASCII_ALPHA | {"+", "-", "."}
TWO_ASCII_HEX_RE = re.compile(r"^[a-fA-F0-9]{2}$")


class ParserState(enum.Enum):
    SCHEME_START = enum.auto()
    SCHEME = enum.auto()
    NO_SCHEME = enum.auto()
    SPECIAL_RELATIVE_OR_AUTHORITY = enum.auto()
    PATH_OR_AUTHORITY = enum.auto()
    RELATIVE = enum.auto()
    RELATIVE_SLASH = enum.auto()
    SPECIAL_AUTHORITY_SLASHES = enum.auto()
    SPECIAL_AUTHORITY_IGNORE_SLASHES = enum.auto()
    AUTHORITY = enum.auto()
    HOST = enum.auto()
    HOSTNAME = enum.auto()
    PORT = enum.auto()
    FILE = enum.auto()
    FILE_SLASH = enum.auto()
    FILE_HOST = enum.auto()
    PATH_START = enum.auto()
    PATH = enum.auto()
    CANNOT_BE_BASE_URL_PATH = enum.auto()
    QUERY = enum.auto()
    FRAGMENT = enum.auto()


class Parser:
    def __init__(
        self,
        url,
        state=ParserState.SCHEME_START,
        encoding="utf-8",
        state_overridden=False,
        base_url=None,
    ):
        self.url: BaseURL = url
        self.base_url: BaseURL = base_url
        self.state = state
        self.state_overridden = state_overridden
        self.encoding = encoding
        self.validation_error = False
        self.failure = False

        self.buffer = ""
        self.pointer = 0
        self.at = False
        self.square_braces = False
        self.password_token_seen = False

    def next_step(self, char: str, remaining: str) -> typing.Optional[bool]:
        if self.state == ParserState.SCHEME_START:
            if char in ASCII_ALPHA:
                self.state = ParserState.SCHEME
                self.buffer += char

            elif not self.state_overridden:
                self.state = ParserState.NO_SCHEME
                self.pointer -= 1

            else:
                self.validation_error = True
                self.failure = True
                return

        elif self.state == ParserState.SCHEME:
            if char in SCHEME:
                self.buffer += char
            elif char == ":":
                if self.state_overridden:
                    if self.url.has_special_scheme != (
                        self.buffer not in SPECIAL_SCHEMES
                    ):
                        return
                    elif self.buffer == "file" and (
                        self.url.has_credentials or not self.url.has_default_port
                    ):
                        return
                    elif self.url.scheme == "file" and self.url.host in (None, ""):
                        return

                self.url = self.url.copy_with(scheme=self.buffer)

                if self.state_overridden:
                    if self.url.has_default_port:
                        self.url.port = None
                    return

                self.buffer = ""

                if self.url.scheme == "file":
                    if not remaining.startswith("//"):
                        self.validation_error = True
                    self.state = ParserState.FILE

                elif self.url.has_special_scheme:
                    if self.base_url and self.base_url.scheme == self.url.scheme:
                        self.state = ParserState.SPECIAL_RELATIVE_OR_AUTHORITY
                    else:
                        self.state = ParserState.SPECIAL_AUTHORITY_SLASHES

                elif remaining.startswith("/"):
                    self.state = ParserState.PATH_OR_AUTHORITY
                    self.pointer += 1

                else:
                    self.state = ParserState.CANNOT_BE_BASE_URL_PATH
                    self.url.cannot_be_base_url = True
                    self.url.path.append("")

            elif not self.state_overridden:
                self.state = ParserState.NO_SCHEME
                self.buffer = ""
                self.pointer = 0
                return True

            else:
                self.validation_error = True
                self.failure = True
                return

        elif self.state == ParserState.NO_SCHEME:
            if self.base_url is None or (
                self.base_url.cannot_be_base_url and char != "#"
            ):
                self.validation_error = True
                self.failure = True
                return

            elif self.base_url.cannot_be_base_url and char == "#":
                self.url = self.url.copy_with(
                    scheme=self.base_url.scheme,
                    path=self.base_url.path,
                    query=self.base_url.query,
                    fragment="",
                    cannot_be_base_url=True
                )
                self.state = ParserState.FRAGMENT

            elif self.base_url.scheme != "file":
                self.state = ParserState.RELATIVE
                self.pointer -= 1

            else:
                self.state = ParserState.FILE
                self.pointer -= 1

        elif self.state == ParserState.SPECIAL_RELATIVE_OR_AUTHORITY:
            if char == "/" and remaining.startswith("/"):
                self.state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES
                self.pointer += 1

            else:
                self.validation_error = True
                self.state = ParserState.RELATIVE
                self.pointer -= 1

        elif self.state == ParserState.PATH_OR_AUTHORITY:
            if char == "/":
                self.state = ParserState.AUTHORITY
            else:
                self.state = ParserState.PATH
                self.pointer -= 1

        elif self.state == ParserState.RELATIVE:
            self.url.scheme = self.base_url.scheme
            if char in ("", "#"):
                self.url = self.url.copy_with(
                    username=self.base_url.username,
                    password=self.base_url.password,
                    host=self.base_url.host,
                    port=self.base_url.port,
                    path=self.base_url.path,
                    query=self.base_url.query
                )

                if char == "#":
                    self.state = ParserState.FRAGMENT

            elif char == "/":
                self.state = ParserState.RELATIVE_SLASH

            elif char == "?":
                self.state = ParserState.QUERY
                self.url.username = self.base_url.username
                self.url.password = self.base_url.password
                self.url.host = self.base_url.host
                self.url.port = self.base_url.port
                self.url.path = self.base_url.path[:]
                self.url.query = ""

            else:
                if self.url.has_special_scheme and char == "\\":
                    self.state = ParserState.RELATIVE_SLASH
                    self.validation_error = True

                else:
                    self.state = ParserState.PATH
                    self.url.username = self.base_url.username
                    self.url.password = self.base_url.password
                    self.url.host = self.base_url.host
                    self.url.port = self.base_url.port
                    self.url.path = self.base_url.path[:]
                    if self.url.path:
                        self.url.path.pop(-1)
                    self.pointer -= 1

        elif self.state == ParserState.RELATIVE_SLASH:
            if self.url.has_special_scheme and char in ("/", "\\"):
                self.state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES
                if char == "\\":
                    self.validation_error = True

            elif char == "/":
                self.state = ParserState.AUTHORITY

            else:
                self.state = ParserState.PATH
                self.url.username = self.base_url.username
                self.url.password = self.base_url.password
                self.url.host = self.base_url.host
                self.url.port = self.base_url.port
                self.pointer -= 1

        elif self.state == ParserState.SPECIAL_AUTHORITY_SLASHES:
            if char == "/" and remaining.startswith("/"):
                self.state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES
                self.pointer += 1

            else:
                self.validation_error = True
                self.state = ParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES
                self.pointer -= 1

        elif self.state == ParserState.SPECIAL_AUTHORITY_SLASHES:
            if char not in ("/", "\\"):
                self.state = ParserState.AUTHORITY
                self.pointer -= 1

            else:
                self.validation_error = True

        elif self.state == ParserState.AUTHORITY:
            if char == "@":
                if self.at:
                    self.buffer = "@" + self.buffer
                self.at = True

                for bufchar in self.buffer:
                    if bufchar == ":":
                        if not self.password_token_seen:
                            self.password_token_seen = True
                            continue

                        if self.password_token_seen:
                            if self.url.password is None:
                                self.url.password = bufchar
                            else:
                                self.url.password += bufchar

                        else:
                            if self.url.username is None:
                                self.url.username = bufchar
                            else:
                                self.url.username += bufchar

                self.buffer = ""

            elif (
                char == ""
                or char in "/?#"
                or (char == "\\" and self.url.has_special_scheme)
            ):
                if self.at and self.buffer == "":
                    self.validation_error = True
                    self.failure = True
                    return

                self.state = ParserState.HOST
                self.pointer -= len(self.buffer) + 1
                self.buffer = ""

            else:
                self.buffer += char

        elif self.state in (ParserState.HOST, ParserState.HOSTNAME):
            if self.state_overridden and self.url.scheme == "file":
                self.state = ParserState.FILE_HOST
                self.pointer -= 1

            elif char == ":" and not self.square_braces:
                if self.buffer == "":
                    self.validation_error = True
                    self.failure = True
                    return

                self.state = ParserState.PORT
                self.host = self.buffer
                self.buffer = ""

                if self.state_overridden == ParserState.HOSTNAME:
                    return

            elif (
                char == ""
                or char in "/?#"
                or (char == "\\" and self.url.has_special_scheme)
            ):
                self.pointer -= 1

                if self.url.has_special_scheme and self.buffer == "":
                    self.validation_error = True
                    self.failure = True
                    return

                elif (
                    self.state_overridden
                    and self.buffer == ""
                    and (self.url.has_credentials or self.url.port is not None)
                ):
                    self.validation_error = True
                    return

                self.state = ParserState.PATH_START
                self.url.host = self.buffer
                self.buffer = ""

                if self.state_overridden:
                    return

            else:
                if char == "[":
                    self.square_braces = True
                elif char == "]":
                    self.square_braces = False
                else:
                    self.buffer += char

        elif self.state == ParserState.PORT:
            if char in ASCII_DIGIT:
                self.buffer += char

            elif (
                self.state_overridden
                or char == ""
                or char in "/?#"
                or (char == "\\" and self.url.has_special_scheme)
            ):
                if self.buffer != "":
                    port = int(self.buffer)
                    if port > 0xFFFF:
                        self.validation_error = True
                        self.failure = True
                        return

                    self.url.port = port
                    if self.url.has_default_port:
                        self.url.port = None

                    self.buffer = ""

                if self.state_overridden:
                    return

                self.state = ParserState.PATH_START
                self.pointer -= 1

            else:
                self.validation_error = True
                self.failure = True
                return

        # TODO
        elif self.state == ParserState.FILE:
            pass
        elif self.state == ParserState.FILE_SLASH:
            pass
        elif self.state == ParserState.FILE_HOST:
            pass
        elif self.state == ParserState.PATH_START:
            pass
        elif self.state == ParserState.PATH:
            pass
        elif self.state == ParserState.CANNOT_BE_BASE_URL_PATH:
            pass

        elif self.state == ParserState.QUERY:
            if self.encoding != "utf-8" and (
                not self.url.has_special_scheme or self.url.scheme in ("ws", "wss")
            ):
                self.encoding = "utf-8"

            if not self.state_overridden and char == "#":
                self.state = ParserState.FRAGMENT
                self.url.fragment = ""

            elif char != "":
                if False:
                    pass  # TODO: URL Code Point check
                elif char == "%" and not TWO_ASCII_HEX_RE.match(remaining[:2]):
                    self.validation_error = True

        elif self.state == ParserState.FRAGMENT:
            if char == "":
                pass
            elif char == "\x00":
                self.validation_error = True
            else:
                if False:
                    pass  # TODO: URL Code Point check
                elif char == "%" and not TWO_ASCII_HEX_RE.match(remaining[:2]):
                    self.validation_error = True
                if self.url.fragment is None:
                    self.url.fragment = char
                else:
                    self.url.fragment += char

        self.pointer += 1
        return True


def parse_url(url: str, base_url=None, policy=None) -> "ParsedURL":
    from .models import ParsedURL

    result = ParsedURL()
    parser = Parser(url=result)
    result = True
    while result:
        char = url[parser.pointer]
        remaining = url[parser.pointer + 1 :]
        print(char, remaining, parser.state)
        result = parser.next_step(char, remaining)

    print(parser.url)
