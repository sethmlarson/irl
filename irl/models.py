import typing
from .utils import CaseInsensitiveSet, CaseInsensitiveDict


# sentinel for defaults
_DEFAULT = object()

SPECIAL_SCHEMES = CaseInsensitiveSet(
    {"ftp", "file", "gopher", "http", "https", "ws", "wss", "ftp", "ssh"}
)
SCHEME_DEFAULT_PORTS = CaseInsensitiveDict(
    {
        "ftp": 21,
        "ssh": 22,
        "gopher": 70,
        "http": 80,
        "ws": 80,
        "https": 443,
        "wss": 443,
        "socks4": 1080,
        "socks4a": 1080,
        "socks5": 1080,
        "socks5h": 1080,
    }
)


class Origin(typing.NamedTuple):
    scheme: typing.Optional[str]
    host: typing.Optional[str]
    port: typing.Optional[int]
    domain: typing.Optional[str]

    def __eq__(self, other):
        if isinstance(other, Origin):
            if self.is_opaque or other.is_opaque:
                return False
            return all(x == y for x, y in zip(self, other))
        return NotImplemented


class BaseURL:
    def __init__(
        self,
        url: typing.Optional[str] = None,
        *,
        scheme: typing.Optional[str] = None,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        host: typing.Optional[str] = None,
        port: typing.Optional[int] = None,
        path: typing.Tuple[str, ...] = None,
        query: typing.Optional[str] = None,
        fragment: typing.Optional[str] = None,
        encoding: str = "utf-8",
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
            fragment = parsed_url.fragment

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
        raise URLError(f"{self!r} doesn't have an effective port")

    @property
    def has_default_port(self) -> bool:
        return self.scheme is not None

    @property
    def has_credentials(self) -> bool:
        return self.username is not None or self.password is not None

    @property
    def has_special_scheme(self) -> bool:
        return self.scheme in SPECIAL_SCHEMES

    @property
    def ipv6_zone_id(self) -> typing.Optional[str]:
        """Returns the IPv6 Zone ID for the URL if any."""

    def normalize(self) -> "BaseURL":
        """Normalizes all parts of the URL for comparisons"""

    def join(self, url: typing.Union[str, "BaseURL"]) -> "BaseURL":
        """Joins the given URL onto the current URL like in the case of an HTTP redirect"""

    def copy_with(
        self,
        *,
        scheme=_DEFAULT,
        username=_DEFAULT,
        password=_DEFAULT,
        host=_DEFAULT,
        port=_DEFAULT,
        path=_DEFAULT,
        query=_DEFAULT,
        fragment=_DEFAULT,
        cannot_be_base_url=_DEFAULT,
    ) -> "BaseURL":
        scheme = self.scheme if scheme is _DEFAULT else scheme
        username = self.username if username is _DEFAULT else username
        password = self.password if password is _DEFAULT else password
        host = self.host if host is _DEFAULT else host
        port = self.port if port is _DEFAULT else port
        path = self.path if path is _DEFAULT else path
        query = self.query if query is _DEFAULT else query
        fragment = self.fragment if fragment is _DEFAULT else fragment
        cannot_be_base_url = self.cannot_be_base_url if cannot_be_base_url is _DEFAULT else cannot_be_base_url

        url = type(self)(
            scheme=scheme,
            username=username,
            password=password,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            cannot_be_base_url=cannot_be_base_url
        )
        return url

    def _parts(self) -> typing.Tuple[typing.Any, ...]:
        return (
            self.scheme,
            self.username,
            self.password,
            self.host,
            self.port,
            self.path,
            self.query,
            self.fragment,
            self.cannot_be_base_url
        )

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
            output.append(self.path[0])
        else:
            for segment in self.path:
                output.extend(("/", segment))
        if self.query is not None:
            output.extend(("?", self.query))
        if self.fragment is not None:
            output.extend(("#", self.fragment))
        return "".join(output)

    def __eq__(self, other) -> bool:
        if not isinstance(other, BaseURL):
            return NotImplemented
        return self._parts() == other._parts()

    def __ne__(self, other) -> bool:
        if not isinstance(other, BaseURL):
            return NotImplemented
        return self._parts() != other._parts()


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
        if the host shouldn't require SNI by default.
        """


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
