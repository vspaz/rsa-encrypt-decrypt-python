import os

import setuptools


def _build_path(file_path, base=os.path.abspath(os.path.dirname(__file__))):
    return os.path.join(base, file_path)


def _get_dependencies():
    with open(_build_path(file_path="requirements/prod.txt")) as fh:
        return [line.strip() for line in fh.readlines()]


def _get_readme():
    with open(_build_path(file_path="README.md")) as fh:
        return fh.read()


def _get_package_info():
    with open(_build_path(file_path="cryptolib/__version__.py")) as fh:
        package_info = {}
        exec(fh.read(), package_info)
        return package_info


_PACKAGE_INFO = _get_package_info()


setuptools.setup(
    name=_PACKAGE_INFO["__title__"],
    version=_PACKAGE_INFO["__version__"],
    description=_PACKAGE_INFO["__description__"],
    long_description=_get_readme(),
    packages=setuptools.find_packages(exclude=["tests", "examples", "requirements"]),
    install_requires=_get_dependencies(),
    url=_PACKAGE_INFO["__url__"],
    license="MIT License",
    author=_PACKAGE_INFO["__author__"],
    author_email=_PACKAGE_INFO["__email__"],
    maintainer=_PACKAGE_INFO["__maintainer__"],
    classifiers=[
        "Programming Language :: Python :: 3"
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12"
        "Programming Language :: Python :: 3.13",
    ],
)
