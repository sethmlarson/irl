import re
import os
from setuptools import setup


base_dir = os.path.abspath(".")
with open(os.path.join(base_dir, "irl.py")) as f:
    version = re.search(r"__version__\s+=\s+\"([\d.]+)\"", f.read()).group(1)

setup(
    name="irl",
    version=version,
    license="MIT",
    long_description=open(os.path.join(base_dir, "README.md")).read(),
    long_description_content_type="text/markdown",
    author="Seth Michael Larson",
    author_email="sethmichaellarson@gmail.com",
    py_modules=["irl"],
    python_requires=">=3.6",
    install_requires=["idna"],
)
