# irl

`irl` is a URL parser library that has a mixture of very strict rules around
a URL's host and port section but very relaxed in all other sections making it
the ideal balance of secure, tolerant, and performant.

It's primary use-case is for being used in HTTP client libraries as they have
to deal with the Internet and lots URLs that are definitely not compliant but
users expect them to work anyways!

## Installation

Supports Python 3.6 or later.

`python -m pip install irl`

## Usage

```python
>>> import irl
>>> url = irl.URL.parse("https://user:pass@example.com:1234/path?q=ue&r=&y#frag")

>>> print(repr(url))
URL(scheme="https", userinfo="user:pass", host="example.com", port=1234, path="/path", query="q=ue&r=&y", fragment="frag")

>>> url.target()
b"/path?qu=e&r=&y"

>>> url.host_header()
b"example.com:1234"

>>> url.query_to_items()
[("q", "ue"), ("r", ""), ("y", None)

>>> url.address()
("example.com", 1234)
```

## Standards Implemented

- [RFC 3986](https://tools.ietf.org/html/rfc3986)
- [RFC 3987](https://tools.ietf.org/html/rfc3987)
- [RFC 4007](https://tools.ietf.org/html/rfc4007)
- [RFC 6874](https://tools.ietf.org/html/rfc6874)

## Acknowledgements

This URL parser library wouldn't be possible without the [rfc3986](https://github.com/python-hyper/rfc3986) library
or the test suite from [urllib3](https://github.com/urllib3/urllib3).  This parser is based
heavily on techniques used in both libraries and they directly inspired this libraries creation.

## License

MIT
