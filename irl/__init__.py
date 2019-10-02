"""URLs for IRL"""

import enum
import typing
import sys


__version__ = "0.2"
__all__ = [
    "parse_url",
    "ParsePolicy",
    "IS_INTERACTIVE_MODE",
    "URLError",
]

# sys.ps1 only exists in interactive mode.
IS_INTERACTIVE_MODE = hasattr(sys, "ps1")

# sentinel for defaults
_DEFAULT = object()

# Default ports by scheme
SCHEME_DEFAULT_PORTS = {
    "ftp": 21,
    "gopher": 70,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "ssh": 22
}
SPECIAL_SCHEMES = {
    "ftp", "file", "gopher", "http", "https", "ws", "wss"
}

# Character Sets
SINGLE_DOT_PATH_SEGMENT = {".", "%2e"}
DOUBLE_DOT_PATH_SEGMENT = {"..", ".%2e", "%2e.", "%2e%2e"}
C0_CONTROL_SET = set([chr(x) for x in range(0x00, 0x20)])
FRAGMENT_SET = C0_CONTROL_SET | {" ", "\"", "<", ">", "`"}
PATH_SET = FRAGMENT_SET | {"#", "?", "{", "}"}
USERINFO_SET = PATH_SET | {"/", ":", ";", "=", "@", "[", "\\", "]", "^", "|"}


class ParsePolicy(enum.Enum):
    HAND_TYPED = "HAND_TYPED"
    LAX = "LAX"
    STRICT = "STRICT"


class URLError(Exception):
    pass


def parse_url(
    url, policy=ParsePolicy.STRICT, encoding="utf-8", default_scheme=None
) -> "ParsedURL":
    """Parses a URL with a given policy"""
    if policy == ParsePolicy.HAND_TYPED and not IS_INTERACTIVE_MODE:
        raise ValueError("ParsePolicy.HAND_TYPED is only allowed in interactive mode")


class Origin(typing.NamedTuple):
    scheme: str
    host: str
    port: int


class BaseURL:
    def __init__(
        self,
        url=None,
        *,
        scheme=None,
        username=None,
        password=None,
        host=None,
        port=None,
        path=None,
        query=None,
        fragment=None,
        encoding="utf-8",
    ):
        if url is not None:
            parsed_url = type(self).loads(url, encoding=encoding)
            scheme = parsed_url.scheme
            username = parsed_url.username
            password = parsed_url.password
            host = parsed_url.host
            port = parsed_url.port
            path = parsed_url.path
            query = parsed_url.query
            fragment =parsed_url.fragment

        self.scheme = scheme
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.path = path
        self.query = query
        self.fragment = fragment
        self.encoding = encoding

        self.cannot_be_base_url: bool = False

    @classmethod
    def loads(cls, url: str, encoding="utf-8") -> "BaseURL":
        pass

    @property
    def effective_port(self) -> int:
        if self.port is not None:
            return self.port
        elif self.scheme is not None and self.scheme in SCHEME_DEFAULT_PORTS:
            return SCHEME_DEFAULT_PORTS[self.scheme]
        raise URLError(f"URL {self!r} doesn't have an effective port")

    @property
    def has_default_port(self) -> bool:
        return self.scheme is not None

    @property
    def has_credentials(self) -> bool:
        return self.username is not None or self.password is not None

    def is_special_url(self) -> bool:
        return self.scheme in SPECIAL_SCHEMES

    def path_segments(self) -> typing.Tuple[str, ...]:
        """Returns a tuple of path segments"""

    def strip_zone_id(self) -> "BaseURL":
        """Removes the IPv6 Zone ID from the URL. Must do this whenever
        using/sending the URL host externally.
        """

    def normalize(self) -> "BaseURL":
        pass

    def copy_with(
        self,
        scheme=_DEFAULT,
        username=_DEFAULT,
        password=_DEFAULT,
        host=_DEFAULT,
        port=_DEFAULT,
        path=_DEFAULT,
        query=_DEFAULT,
        fragment=_DEFAULT,
    ) -> "BaseURL":
        pass

    def __str__(self) -> str:
        output = [self.scheme + ":"]
        if self.host:
            output.append("//")
            if self.has_credentials:
                output.append(self.username)
                if self.password is not None:
                    output.extend((":", self.password))
                output.append("@")
            output.append(self.host)
            if self.port is not None:
                output.extend((":", str(self.port)))
        elif self.scheme == "file":
            output.append("//")
        if self.cannot_be_base_url:
            output.append(self.path_segments[0])
        else:
            for segment in self.path_segments:
                output.extend(("/", segment))
        if self.query is not None:
            output.extend(("?", self.query))
        if self.fragment is not None:
            output.extend(("#", self.fragment))
        return "".join(output)

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} "
            f"scheme={self.scheme!r} "
            f"username={self.username!r} "
            f"password={self.password!r} "
            f"host={self.host!r} "
            f"port={self.port!r} "
            f"path={self.path!r} "
            f"query={self.query!r} "
            f"fragment={self.fragment!r}>"
        )


class ParsedURL(BaseURL):
    """A URL that has been freshly parsed and hasn't been shunted into either
    the 'encoded' or 'decoded' category. This URL shouldn't live very long
    and should either have .encode() or .decode() called on it so your use-case
    is more defined.

    This URL can be a mixed bag of encoded and decoded. For example:

        'https://user@domain.com@xn--bcher-kva.com/'

    The above URL has a properly encoded host component but the
    username component has an illegal '@' character within it
    which should be percent-encoded for that component. Here's
    how calling .decode() and .encode() would change the URL:

        .decode() -> DecodedURL(username='user%40domain.com', host='xn--bcher-kva.com')
        .encode() -> EncodedURL(username='user@domain.com', host='bücher.com')
    """

    def decode(self, encoding="utf-8") -> "DecodedURL":
        pass

    def encode(self, encoding="utf-8") -> "EncodedURL":
        pass


class EncodedURL(BaseURL):
    """A URL class that is percent-encoded and ready for to be sent on wire."""

    def decode(self, encoding="utf-8") -> "DecodedURL":
        pass

    @property
    def origin(self) -> Origin:
        pass

    def socket_address(self) -> typing.Tuple[str, int]:
        host = self.host
        if host[0] == "[" and host[-1] == "]":
            host = host[1:-1]
        return host, self.effective_port

    def unix_path(self) -> str:
        """Path if the URL has scheme='http+unix' to bind a UNIX socket to"""

    def http_v1_headers(self) -> typing.List[typing.Tuple[bytes, bytes]]:
        """List of headers to be added for HTTP/1.X"""
        host_header = self.strip_zone_id().host.encode()
        if self.has_default_port:
            host_header += b":" + str(self.effective_port).encode()
        return [(b"Host", host_header)]

    def http_v2_and_v3_headers(
        self, path: bytes = None
    ) -> typing.List[typing.Tuple[bytes, bytes]]:
        """List of headers to be used for HTTP/2 and HTTP/3"""
        host_header = self.strip_zone_id().host
        return [
            (b":authority", f"{host_header}:{self.effective_port}".encode()),
            (b":scheme", self.scheme.encode()),
            (b":path", path or self.http_request_target().encode()),
        ]

    def http_connect_target(self) -> str:
        """The HTTP 'target' for a CONNECT request when creating a tunnel proxy"""
        host_header = self.strip_zone_id().host
        return f"{host_header}:{self.effective_port}"

    def http_request_target(self) -> str:
        """The HTTP 'target' for a normal HTTP request"""
        target = self.path
        if self.query is not None:
            target += "?" + self.query
        return target

    def tls_server_hostname(self) -> typing.Optional[str]:
        """The TLS SNI hostname to use for this URL. Will be 'None'
        if the host """


class DecodedURL(BaseURL):
    """A URL class that is suitable for representing a URL for humans
    and exposing to application-level consumers.
    """

    def encode(self, encoding="utf-8") -> "EncodedURL":
        pass

    def for_human_eyes(self) -> str:
        """Renders the URL for display purposes"""

    def http_basic_auth(self) -> str:
        """The base64-encoded value for use in HTTP Basic Auth"""
