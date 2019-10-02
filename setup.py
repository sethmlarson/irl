import re
import pathlib
from setuptools import setup


base_dir = pathlib.Path(__file__).parent
with open(base_dir / "irl" / "__init__.py") as f:
    version = re.search(r"__version__\s+=\s+\"([\d.]+)\"", f.read()).group(1)

setup(
    name="irl",
    version=version,
    license="MIT",
    long_description=open(base_dir / "README.md", "r").read(),
    long_description_content_type="text/markdown",
    author="Seth Michael Larson",
    author_email="sethmichaellarson@gmail.com",
    packages=["irl"],
    package_data={"irl": ["py.typed"]},
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.6",
    install_requires=["idna", "homoglyphs"],
)
