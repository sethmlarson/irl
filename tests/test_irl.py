import pytest
import irl


def test_equality_on_normalize():
    url1 = irl.URL.parse("http://ヒ.example.com/abc%af?ヒq%CC#%dE")
    url2 = irl.URL.parse("HTTP://xn--pdk.eXaMpLe.CoM/abc%AF?%E3%83%92q%cc#%De")

    assert url1 == url2


@pytest.mark.parametrize(
    ["url", "addr"],
    [
        ("http://example.com", ("example.com", 80)),
        ("https://example.com", ("example.com", 443)),
        ("https://example.com:1337", ("example.com", 1337)),
        ("http://[::1]:1", ("::1", 1)),
        ("http://[ffff::1%eth0]:443", ("ffff::1%eth0", 443)),
        ("http://[ffff::1%25eth0]:80", ("ffff::1%eth0", 80)),
    ],
)
def test_url_to_address(url, addr):
    assert irl.URL.parse(url).address() == addr


@pytest.mark.parametrize(
    "url", ["httpq://example.com/", "/google.com", "http+unix://%2Ftmp%2Fdocker.sock"]
)
def test_unknown_host_or_port_on_address(url):
    url = irl.URL.parse(url)
    with pytest.raises(irl.URLError):
        url.address()
