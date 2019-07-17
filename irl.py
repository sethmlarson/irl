import re
import typing
from urllib.parse import urljoin


__all__ = ["URL", "URLError"]
__version__ = "0.2"


# fmt: off

# Almost all of these patterns were taken or derived from the
# 'rfc3986' module: https://github.com/python-hyper/rfc3986
PERCENT_RE = re.compile(r"%[a-fA-F0-9]{2}")
SCHEME_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+-]*:|/)")
URI_RE = re.compile(
    r"^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?"
    r"(?://([^/?#]*))?"
    r"([^?#]*)"
    r"(?:\?([^#]*))?"
    r"(?:#(.*))?$",
    re.UNICODE | re.DOTALL
)

IPV4_PAT = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
HEX_PAT = "[0-9A-Fa-f]{1,4}"
LS32_PAT = "(?:{hex}:{hex}|{ipv4})".format(hex=HEX_PAT, ipv4=IPV4_PAT)
_subs = {"hex": HEX_PAT, "ls32": LS32_PAT}
_variations = [
    #                            6( h16 ":" ) ls32
    "(?:%(hex)s:){6}%(ls32)s",
    #                       "::" 5( h16 ":" ) ls32
    "::(?:%(hex)s:){5}%(ls32)s",
    # [               h16 ] "::" 4( h16 ":" ) ls32
    "(?:%(hex)s)?::(?:%(hex)s:){4}%(ls32)s",
    # [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
    "(?:(?:%(hex)s:)?%(hex)s)?::(?:%(hex)s:){3}%(ls32)s",
    # [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
    "(?:(?:%(hex)s:){0,2}%(hex)s)?::(?:%(hex)s:){2}%(ls32)s",
    # [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
    "(?:(?:%(hex)s:){0,3}%(hex)s)?::%(hex)s:%(ls32)s",
    # [ *4( h16 ":" ) h16 ] "::"              ls32
    "(?:(?:%(hex)s:){0,4}%(hex)s)?::%(ls32)s",
    # [ *5( h16 ":" ) h16 ] "::"              h16
    "(?:(?:%(hex)s:){0,5}%(hex)s)?::%(hex)s",
    # [ *6( h16 ":" ) h16 ] "::"
    "(?:(?:%(hex)s:){0,6}%(hex)s)?::",
]

UNRESERVED_PAT = r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._!\-"
IPV6_PAT = "(?:" + "|".join([x % _subs for x in _variations]) + ")"
ZONE_ID_PAT = "(?:%25|%)(?:[" + UNRESERVED_PAT + "]|%[a-fA-F0-9]{2})+"
IPV6_ADDRZ_PAT = r"\[" + IPV6_PAT + r"(?:" + ZONE_ID_PAT + r")?\]"
REG_NAME_PAT = r"(?:[^\[\]%:/?#]|%[a-fA-F0-9]{2})*"

IPV4_RE = re.compile("^" + IPV4_PAT + "$")
IPV6_RE = re.compile("^" + IPV6_PAT + "$")
IPV6_ADDRZ_RE = re.compile("^" + IPV6_ADDRZ_PAT + "$")
ZONE_ID_RE = re.compile("(" + ZONE_ID_PAT + r")\]$")

SUBAUTHORITY_PAT = (
    "^(?:(.*)@)?"
    "(%s|%s|%s)"
    "(?::([0-9]{0,5}))?$"
) % (REG_NAME_PAT, IPV4_PAT, IPV6_ADDRZ_PAT)
SUBAUTHORITY_RE = re.compile(
    SUBAUTHORITY_PAT,
    re.UNICODE | re.DOTALL,
)

ZONE_ID_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789._!-"
)
USERINFO_CHARS = ZONE_ID_CHARS | set(
    "$&'()*+,;=:"
)
PATH_CHARS = USERINFO_CHARS | {"@", "/"}
QUERY_CHARS = FRAGMENT_CHARS = PATH_CHARS | {"?"}

DEFAULT_PORTS: typing.Dict[str, int] = {
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
NORMALIZABLE_SCHEMES = {None, "http", "https"}

# fmt: on


class URLError(Exception):
    pass


class URL(typing.NamedTuple):
    scheme: typing.Optional[str]
    userinfo: typing.Optional[str]
    host: typing.Optional[str]
    port: typing.Optional[int]
    path: typing.Optional[str]
    query: typing.Optional[str]
    fragment: typing.Optional[str]

    @classmethod
    def parse(cls, url: str) -> "URL":
        if not url:
            return URL(None, None, None, None, None, None, None)

        # Special case because 'localhost' definitely isn't a
        # scheme and it's almost certainly a host so we treat
        # 'localhost:...' cases specially.
        if not SCHEME_RE.search(url) or (
            url.startswith("localhost:") and not url.startswith("localhost://")
        ):
            url = "//" + url

        try:
            scheme, authority, path, query, fragment = URI_RE.match(url).groups()

            # Schemes are always case-insensitive so we lowercase
            if scheme:
                scheme = scheme.lower()
            is_normalizable = scheme in NORMALIZABLE_SCHEMES

            if authority:
                userinfo, host, port = SUBAUTHORITY_RE.match(authority).groups()

                # Ports when empty we just ignore them.
                if port == "":
                    port = None
            else:
                userinfo, host, port = None, None, None

            # Ports are allowed to be 0-65535 to fit into 2 bytes.
            if port is not None:
                port = int(port)
                if not (0 <= port <= 65535):
                    raise URLError(f"Port {port} is out of range 0-65535")

            host = _normalize_host(host, scheme)

            # Userinfo, Path, Query, and Fragment can all have
            # percent-encoded characters
            if is_normalizable:
                userinfo = _encode_invalid_chars(userinfo, USERINFO_CHARS)
                path = _normalize_path(path)
                query = _encode_invalid_chars(query, QUERY_CHARS)
                fragment = _encode_invalid_chars(fragment, FRAGMENT_CHARS)

        except (ValueError, AttributeError):
            raise URLError(f"Unable to parse the URL {url!r}") from None

        return URL(
            scheme=scheme,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
        )

    def target(self) -> bytes:
        """Gets the HTTP target (or ':path' for HTTP/2+) of a
        non-OPTIONS/CONNECT request for this URL.
        """
        target = (self.path or "/").encode()
        if self.query is not None:
            target += b"?" + self.query.encode()
        return target

    def host_header(self) -> bytes:
        """Gets the value of the 'Host' (or ':authority' for HTTP/2+)
        of a request for this URL.
        """
        if self.host is None:
            raise URLError("Unable to create 'Host' header without host")

        # Zone ID shouldn't be sent in the 'Host' header as it's not
        # relevant outside of the client machine to pick a network interface.
        header = _remove_ipv6_zone_id(self.host).encode()

        if self.port is not None:
            header += b":" + str(self.port).encode()

        return header

    def address(self) -> typing.Tuple[str, int]:
        """Gets the address tuple to be used by socket.create_connection() and the like.
        Raises an error if we can't determine what the host or port should be.
        """
        if self.host is None:
            raise URLError("Unable to get a 'host' for address()")
        host = self.host
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        port = self.port_with_defaults()
        if port is None:
            raise URLError("Unable to get a 'port' for address()")
        return host, port

    def redirect(self, rel: str) -> "URL":
        """Joins a relative or absolute URL onto this URL.
        Don't allow external services to decide an IPv6 Zone ID for us.
        """
        url = URL.parse(urljoin(self.unsplit(), rel))
        url.host = _remove_ipv6_zone_id(url.host)
        return url

    def normalize(self) -> "URL":
        return URL.parse(self.unsplit())

    def unsplit(self) -> str:
        parts = []
        if self.scheme is not None:
            parts.extend((self.scheme, ":"))
        if self.host is not None:
            if self.scheme is not None:
                parts.append("//")
            if self.userinfo is not None:
                parts.append(self.userinfo + "@")
            parts.append(self.host)
            if self.port is not None:
                parts.append(":" + str(self.port))
        if self.path is not None:
            parts.append(self.path)
        if self.query is not None:
            parts.append("?" + self.query)
        if self.fragment is not None:
            parts.append("#" + self.fragment)
        return "".join(parts)

    def port_with_defaults(self) -> typing.Optional[int]:
        if self.port is None and self.scheme in DEFAULT_PORTS:
            return DEFAULT_PORTS[self.scheme]
        return self.port

    def __str__(self):
        return self.unsplit()

    def __eq__(self, other):
        if not isinstance(other, URL):  # pragma: nocover
            return NotImplemented
        return tuple(self.normalize()) == tuple(other.normalize())

    def __ne__(self, other):
        if not isinstance(other, URL):  # pragma: nocover
            return NotImplemented
        return tuple(self.normalize()) != tuple(other.normalize())


# Sets all parameter defaults to 'None'
URL.__new__.__defaults__ = (None,) * len(URL._fields)


def _encode_invalid_chars(
    component: typing.Optional[str], allowed_chars: typing.Set[str]
) -> typing.Optional[str]:
    """Percent-encodes a URI component without reapplying
    onto an already percent-encoded component.
    """

    if component is None:
        return component

    # Try to see if the component we're encoding is already percent-encoded
    # so we can skip all '%' characters but still encode all others.
    percent_encodings = PERCENT_RE.findall(component)

    # Normalize existing percent-encoded bytes.
    for enc in percent_encodings:
        if not enc.isupper():
            component = component.replace(enc, enc.upper())

    uri_bytes = component.encode("utf-8", "surrogatepass")
    is_percent_encoded = len(percent_encodings) == uri_bytes.count(b"%")

    encoded_component = bytearray()

    for i in range(0, len(uri_bytes)):
        byte = uri_bytes[i : i + 1]
        byte_ord = ord(byte)
        if (is_percent_encoded and byte == b"%") or (
            byte_ord < 128 and byte.decode() in allowed_chars
        ):
            encoded_component.extend(byte)
            continue
        encoded_component.extend(b"%" + (hex(byte_ord)[2:].encode().zfill(2).upper()))

    return encoded_component.decode("ascii")


def _normalize_path(path: str) -> str:
    segments = path.split("/")  # Turn the path into a list of segments
    output = []  # Initialize the variable to use to store output

    for segment in segments:
        # '.' is the current directory, so ignore it, it is superfluous
        if segment == ".":
            continue
        # Anything other than '..', should be appended to the output
        elif segment != "..":
            output.append(segment)
        # In this case segment == '..', if we can, we should pop the last
        # element
        elif output:
            output.pop()

    # If the path starts with '/' and the output is empty or the first string
    # is non-empty
    if path.startswith("/") and (not output or output[0]):
        output.insert(0, "")

    # If the path starts with '/.' or '/..' ensure we add one more empty
    # string to add a trailing '/'
    if path.endswith(("/.", "/..")):
        output.append("")

    return _encode_invalid_chars("/".join(output), PATH_CHARS)


def _normalize_host(
    host: typing.Optional[str], scheme: typing.Optional[str]
) -> typing.Optional[str]:
    """Normalizes the host component of a URL"""
    if host:
        if scheme in NORMALIZABLE_SCHEMES:
            if IPV6_ADDRZ_RE.match(host):
                match = ZONE_ID_RE.search(host)

                # IPV6 with Zone ID
                if match:
                    start, end = match.span(1)
                    zone_id = host[start:end]

                    # Handle a RFC 6874-style Zone ID delimiter and
                    # transform it into just a '%' so it can be used
                    # within socket.gethostbyname()
                    if zone_id.startswith("%25") and zone_id != "%25":
                        zone_id = zone_id[3:]

                    # Usual RFC 4007-style Zone ID delimiter
                    else:
                        zone_id = zone_id[1:]

                    zone_id = "%" + _encode_invalid_chars(zone_id, ZONE_ID_CHARS)
                    return host[:start].lower() + zone_id + host[end:]

                # IPV6 without a Zone ID
                else:
                    return host.lower()

            # REG-NAME
            elif not IPV4_RE.match(host):
                return ".".join([_idna_encode(label) for label in host.split(".")])
    return host


def _idna_encode(name: str) -> str:
    """IDNA-encoded a single label within a REG-NAME hostname"""
    if name and any(ord(x) > 0x7F for x in name):
        import idna

        try:
            return idna.encode(name.lower(), strict=True, std3_rules=True).decode(
                "ascii"
            )
        except idna.IDNAError:
            raise URLError(f"{name!r} is not a valid IDN-label")
    return name.lower()


def _remove_ipv6_zone_id(host: typing.Optional[str]) -> typing.Optional[str]:
    if host and IPV6_ADDRZ_RE.match(host):
        match = ZONE_ID_RE.search(host)
        if match:
            start, end = match.span(1)
            return host[:start] + host[end:]
    return host
