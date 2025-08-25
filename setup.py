from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dehashed-api",
    version="0.2.0",
    author="SUT0L",
    author_email="117520656+SUT0L@users.noreply.github.com",
    description="Unofficial Python client for the DeHashed Web-API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SUT0L/unofficial-dehashed-api/",
    packages=find_packages(exclude=["examples", "examples.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.11.16",
        "requests>=2.32.3",
        "pycryptodome>=3.10.0",
    ],
    extras_require={
        "orjson": ["orjson>=3.10.16"],
        "ujson": ["ujson>=5.10.0"]
    },
)
