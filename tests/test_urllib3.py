# urllib3's test suite for URLs

import pytest
import irl


url_origin_map = [
    # Hosts
    ("http://google.com/mail", ("http", "google.com", None)),
    ("http://google.com/mail/", ("http", "google.com", None)),
    ("http://google.com/", ("http", "google.com", None)),
    ("http://google.com", ("http", "google.com", None)),
    ("http://www.google.com", ("http", "www.google.com", None)),
    ("http://mail.google.com", ("http", "mail.google.com", None)),
    ("http://google.com:8000/mail/", ("http", "google.com", 8000)),
    ("http://google.com:8000", ("http", "google.com", 8000)),
    ("https://google.com", ("https", "google.com", None)),
    ("https://google.com:0", ("https", "google.com", 0)),
    ("https://google.com:8000", ("https", "google.com", 8000)),
    ("https://google.com:65535", ("https", "google.com", 0xFFFF)),
    ("http://user:password@127.0.0.1:1234", ("http", "127.0.0.1", 1234)),
    ("http://google.com/foo=http://bar:42/baz", ("http", "google.com", None)),
    ("http://google.com?foo=http://bar:42/baz", ("http", "google.com", None)),
    ("http://google.com#foo=http://bar:42/baz", ("http", "google.com", None)),
    # IPv4
    ("http://173.194.35.7", ("http", "173.194.35.7", None)),
    ("http://173.194.35.7/test", ("http", "173.194.35.7", None)),
    ("http://173.194.35.7:80", ("http", "173.194.35.7", 80)),
    ("http://173.194.35.7:80/test", ("http", "173.194.35.7", 80)),
    # IPv6
    ("http://[2a00:1450:4001:c01::67]", ("http", "[2a00:1450:4001:c01::67]", None)),
    (
        "http://[2a00:1450:4001:c01::67]/test",
        ("http", "[2a00:1450:4001:c01::67]", None),
    ),
    ("http://[2a00:1450:4001:c01::67]:80", ("http", "[2a00:1450:4001:c01::67]", 80)),
    (
        "http://[2a00:1450:4001:c01::67]:80/test",
        ("http", "[2a00:1450:4001:c01::67]", 80),
    ),
    # More IPv6 from http://www.ietf.org/rfc/rfc2732.txt
    (
        "http://[fedc:ba98:7654:3210:fedc:ba98:7654:3210]:8000/index.html",
        ("http", "[fedc:ba98:7654:3210:fedc:ba98:7654:3210]", 8000),
    ),
    (
        "http://[1080:0:0:0:8:800:200c:417a]/index.html",
        ("http", "[1080:0:0:0:8:800:200c:417a]", None),
    ),
    ("http://[3ffe:2a00:100:7031::1]", ("http", "[3ffe:2a00:100:7031::1]", None)),
    ("http://[1080::8:800:200c:417a]/foo", ("http", "[1080::8:800:200c:417a]", None)),
    ("http://[::192.9.5.5]/ipng", ("http", "[::192.9.5.5]", None)),
    (
        "http://[::ffff:129.144.52.38]:42/index.html",
        ("http", "[::ffff:129.144.52.38]", 42),
    ),
    (
        "http://[2010:836b:4179::836b:4179]",
        ("http", "[2010:836b:4179::836b:4179]", None),
    ),
    # Hosts
    ("HTTP://GOOGLE.COM/mail/", ("http", "google.com", None)),
    ("HTTP://GoOgLe.CoM:8000/mail/", ("http", "google.com", 8000)),
    ("HTTP://user:password@EXAMPLE.COM:1234", ("http", "example.com", 1234)),
    ("HTTP://173.194.35.7", ("http", "173.194.35.7", None)),
    (
        "HTTP://[2a00:1450:4001:c01::67]:80/test",
        ("http", "[2a00:1450:4001:c01::67]", 80),
    ),
    (
        "HTTP://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:8000/index.html",
        ("http", "[fedc:ba98:7654:3210:fedc:ba98:7654:3210]", 8000),
    ),
    (
        "HTTPS://[1080:0:0:0:8:800:200c:417A]/index.html",
        ("https", "[1080:0:0:0:8:800:200c:417a]", None),
    ),
    ("abOut://eXamPlE.com?info=1", ("about", "eXamPlE.com", None)),
    (
        "http+UNIX://%2fvar%2frun%2fSOCKET/path",
        ("http+unix", "%2fvar%2frun%2fSOCKET", None),
    ),
]


@pytest.mark.parametrize(["url", "origin"], url_origin_map)
def test_origin(url, origin):
    url = irl.URL.parse(url)
    assert (url.scheme, url.host, url.port) == origin


@pytest.mark.parametrize(
    "url",
    [
        # Invalid IPv6
        "http://::1/",
        "http://::1:80/",
        "http://[::1",
        "http://::1]"
        # Invalid port
        "http://google.com:foo",
        "http://google.com:-80",
        "http://google.com:\xb2\xb2",
        "http://google.com:65536",
        # Invalid IDNA labels
        "http://\uD7FF.com",
        "http://❤️",
        # Unicode surrogates
        "http://\uD800.com",
        "http://\uDC00.com",
    ],
)
def test_invalid_url(url):
    with pytest.raises(irl.URLError):
        irl.URL.parse(url)


@pytest.mark.parametrize(
    "url, expected_normalized_url",
    [
        ("HTTP://GOOGLE.COM/MAIL/", "http://google.com/MAIL/"),
        (
            "HTTP://JeremyCline:Hunter2@Example.com:8080/",
            "http://JeremyCline:Hunter2@example.com:8080/",
        ),
        ("HTTPS://Example.Com/?Key=Value", "https://example.com/?Key=Value"),
        ("Https://Example.Com/#Fragment", "https://example.com/#Fragment"),
        ("[::1%25]", "[::1%25]"),
        ("[::Ff%etH0%Ff]/%ab%Af", "[::ff%etH0%FF]/%AB%AF"),
        (
            "http://user:pass@[AaAa::Ff%25etH0%Ff]/%ab%Af",
            "http://user:pass@[aaaa::ff%etH0%FF]/%AB%AF",
        ),
        # Invalid characters for the query/fragment getting encoded
        (
            'http://google.com/p[]?parameter[]="hello"#fragment#',
            "http://google.com/p%5B%5D?parameter%5B%5D=%22hello%22#fragment%23",
        ),
        # Percent encoding isn't applied twice despite '%' being invalid
        # but the percent encoding is still normalized.
        (
            "http://google.com/p%5B%5d?parameter%5b%5D=%22hello%22#fragment%23",
            "http://google.com/p%5B%5D?parameter%5B%5D=%22hello%22#fragment%23",
        ),
    ],
)
def test_parse_url_normalization(url, expected_normalized_url):
    """Assert parse_url normalizes the scheme/host, and only the scheme/host"""
    actual_normalized_url = irl.URL.parse(url).unsplit()
    assert actual_normalized_url == expected_normalized_url


@pytest.mark.parametrize("char", [chr(i) for i in range(0x00, 0x21)] + ["\x7F"])
def test_control_characters_are_percent_encoded(char):
    percent_char = "%" + (hex(ord(char))[2:].zfill(2).upper())
    url = irl.URL.parse(
        "http://user{0}@example.com/path{0}?query{0}#fragment{0}".format(char)
    )

    assert url == irl.URL(
        scheme="http",
        userinfo="user" + percent_char,
        host="example.com",
        path="/path" + percent_char,
        query="query" + percent_char,
        fragment="fragment" + percent_char,
    )


parse_url_host_map = [
    ("http://google.com/mail", irl.URL(scheme="http", host="google.com", path="/mail")),
    (
        "http://google.com/mail/",
        irl.URL(scheme="http", host="google.com", path="/mail/"),
    ),
    ("http://google.com/mail", irl.URL(scheme="http", host="google.com", path="/mail")),
    ("google.com/mail", irl.URL(host="google.com", path="/mail")),
    ("http://google.com/", irl.URL(scheme="http", host="google.com", path="/")),
    ("http://google.com", irl.URL(scheme="http", host="google.com")),
    (
        "http://google.com?foo",
        irl.URL(scheme="http", host="google.com", path="", query="foo"),
    ),
    # Path/query/fragment
    ("", irl.URL()),
    ("/", irl.URL(path="/")),
    ("#?/!google.com/?foo", irl.URL(path="", fragment="?/!google.com/?foo")),
    ("/foo", irl.URL(path="/foo")),
    ("/foo?bar=baz", irl.URL(path="/foo", query="bar=baz")),
    (
        "/foo?bar=baz#banana?apple/orange",
        irl.URL(path="/foo", query="bar=baz", fragment="banana?apple/orange"),
    ),
    (
        "/redirect?target=http://localhost:61020/",
        irl.URL(path="/redirect", query="target=http://localhost:61020/"),
    ),
    # Port
    ("http://google.com/", irl.URL(scheme="http", host="google.com", path="/")),
    (
        "http://google.com:80/",
        irl.URL(scheme="http", host="google.com", port=80, path="/"),
    ),
    ("http://google.com:80", irl.URL(scheme="http", host="google.com", port=80)),
    # Auth
    (
        "http://foo:bar@localhost/",
        irl.URL(scheme="http", userinfo="foo:bar", host="localhost", path="/"),
    ),
    (
        "http://foo@localhost/",
        irl.URL(scheme="http", userinfo="foo", host="localhost", path="/"),
    ),
    (
        "http://foo:bar@localhost/",
        irl.URL(scheme="http", userinfo="foo:bar", host="localhost", path="/"),
    ),
    (
        "http://foo:bar@localhost/",
        irl.URL(scheme="http", userinfo="foo:bar", host="localhost", path="/"),
    ),
    (
        "http://foo:bar@localhost/",
        irl.URL(scheme="http", userinfo="foo:bar", host="localhost", path="/"),
    ),
    # Localhost special case
    ("localhost:80/", irl.URL(host="localhost", port=80, path="/")),
    ("localhost", irl.URL(host="localhost")),
    # If it really doesn't look like a host though we aren't fooled
    ("localhost://www.google.com", irl.URL(scheme="localhost", host="www.google.com")),
    (
        "localhost:pass@www.google.com",
        irl.URL(userinfo="localhost:pass", host="www.google.com"),
    ),
]

non_round_tripping_parse_url_host_map = [
    # Path/query/fragment
    ("?", irl.URL(path="", query="")),
    ("#", irl.URL(path="", fragment="")),
    # Path normalization
    ("/abc/../def", irl.URL(path="/def")),
    # Empty Port
    ("http://google.com:", irl.URL(scheme="http", host="google.com")),
    ("http://google.com:/", irl.URL(scheme="http", host="google.com", path="/")),
    # Uppercase IRI
    (
        "http://Königsgäßchen.de/straße",
        irl.URL(scheme="http", host="xn--knigsgchen-b4a3dun.de", path="/stra%C3%9Fe"),
    ),
    # Percent-encode in userinfo
    (
        "http://user@email.com:password@example.com/",
        irl.URL(
            scheme="http",
            userinfo="user%40email.com:password",
            host="example.com",
            path="/",
        ),
    ),
    (
        'http://user":quoted@example.com/',
        irl.URL(scheme="http", userinfo="user%22:quoted", host="example.com", path="/"),
    ),
    # Unicode Surrogates
    (
        "http://google.com/\uD800",
        irl.URL(scheme="http", host="google.com", path="/%ED%A0%80"),
    ),
    (
        "http://google.com?q=\uDC00",
        irl.URL(scheme="http", host="google.com", path="", query="q=%ED%B0%80"),
    ),
    (
        "http://google.com#\uDC00",
        irl.URL(scheme="http", host="google.com", path="", fragment="%ED%B0%80"),
    ),
    # Localhost with empty port
    ("localhost:", irl.URL(host="localhost")),
]


@pytest.mark.parametrize(
    "url, expected_url", parse_url_host_map + non_round_tripping_parse_url_host_map
)
def test_parse(url, expected_url):
    returned_url = irl.URL.parse(url)
    assert returned_url == expected_url


@pytest.mark.parametrize("url, expected_url", parse_url_host_map)
def test_unsplit(url, expected_url):
    assert url == expected_url.unsplit()


@pytest.mark.parametrize(
    ["url", "expected_url"],
    [
        # RFC 3986 5.2.4
        ("/abc/../def", irl.URL(path="/def")),
        ("/..", irl.URL(path="/")),
        ("/./abc/./def/", irl.URL(path="/abc/def/")),
        ("/.", irl.URL(path="/")),
        ("/./", irl.URL(path="/")),
        ("/abc/./.././d/././e/.././f/./../../ghi", irl.URL(path="/ghi")),
    ],
)
def test_parse_and_normalize_url_paths(url, expected_url):
    actual_url = irl.URL.parse(url)
    assert actual_url == expected_url
    assert actual_url.unsplit() == expected_url.unsplit()


def test_url_str():
    url = irl.URL(scheme="http", host="google.com")
    assert str(url) == url.unsplit()


target_map = [
    ("http://google.com/mail", b"/mail"),
    ("http://google.com/mail/", b"/mail/"),
    ("http://google.com/", b"/"),
    ("http://google.com", b"/"),
    ("", b"/"),
    ("/", b"/"),
    ("?", b"/?"),
    ("#", b"/"),
    ("/foo?bar=baz", b"/foo?bar=baz"),
]


@pytest.mark.parametrize("url, expected_target", target_map)
def test_target(url, expected_target):
    returned_url = irl.URL.parse(url)
    assert returned_url.target() == expected_target


url_host_header_map = [
    ("http://google.com/mail", b"google.com"),
    ("http://google.com:80/mail", b"google.com:80"),
    ("google.com/foobar", b"google.com"),
    ("google.com:12345", b"google.com:12345"),
    ("http://[::1%eth0]:80/", b"[::1]:80"),
    ("http://[::1%25eth0]/", b"[::1]"),
]


@pytest.mark.parametrize("url, expected_host_header", url_host_header_map)
def test_host_header(url, expected_host_header):
    assert irl.URL.parse(url).host_header() == expected_host_header


url_vulnerabilities = [
    # urlparse doesn't follow RFC 3986 Section 3.2
    (
        "http://google.com#@evil.com/",
        irl.URL(scheme="http", host="google.com", path="", fragment="@evil.com/"),
    ),
    # CVE-2016-5699
    (
        "http://127.0.0.1%0d%0aConnection%3a%20keep-alive",
        irl.URL(scheme="http", host="127.0.0.1%0d%0aconnection%3a%20keep-alive"),
    ),
    # NodeJS unicode -> double dot
    (
        "http://google.com/\uff2e\uff2e/abc",
        irl.URL(scheme="http", host="google.com", path="/%EF%BC%AE%EF%BC%AE/abc"),
    ),
    # Scheme without ://
    (
        "javascript:a='@google.com:12345/';alert(0)",
        irl.URL(scheme="javascript", path="a='@google.com:12345/';alert(0)"),
    ),
    ("//google.com/a/b/c", irl.URL(host="google.com", path="/a/b/c")),
    # International URLs
    (
        "http://ヒ:キ@ヒ.abc.ニ/ヒ?キ#ワ",
        irl.URL(
            "http",
            host="xn--pdk.abc.xn--idk",
            userinfo="%E3%83%92:%E3%82%AD",
            path="/%E3%83%92",
            query="%E3%82%AD",
            fragment="%E3%83%AF",
        ),
    ),
    # Injected headers (CVE-2016-5699, CVE-2019-9740, CVE-2019-9947)
    (
        "10.251.0.83:7777?a=1 HTTP/1.1\r\nX-injected: header",
        irl.URL(
            host="10.251.0.83",
            port=7777,
            path="",
            query="a=1%20HTTP/1.1%0D%0AX-injected:%20header",
        ),
    ),
    (
        "http://127.0.0.1:6379?\r\nSET test failure12\r\n:8080/test/?test=a",
        irl.URL(
            scheme="http",
            host="127.0.0.1",
            port=6379,
            path="",
            query="%0D%0ASET%20test%20failure12%0D%0A:8080/test/?test=a",
        ),
    ),
]


@pytest.mark.parametrize("url, expected_url", url_vulnerabilities)
def test_url_vulnerabilities(url, expected_url):
    if expected_url is False:
        with pytest.raises(irl.URLError):
            irl.URL.parse(url)
    else:
        assert irl.URL.parse(url) == expected_url
