import typing


class CaseInsensitiveSet(set):
    def add(self, x: typing.Optional[str]) -> None:
        super().add(self._normalize(x))

    def __contains__(self, item: typing.Optional[str]) -> bool:
        return super().__contains__(self._normalize(item))

    def _normalize(self, x: typing.Optional[str]) -> typing.Optional[str]:
        return x.lower() if x else x


class CaseInsensitiveDict(dict):
    def __getattr__(self, item):
        return super().__getitem__(self._normalize(item))

    def __setattr__(self, key, value):
        return super().__setitem__(self._normalize(key), value)

    def _normalize(self, x: typing.Optional[str]) -> typing.Optional[str]:
        return x.lower() if x else x
