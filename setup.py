# setup.py for packaging
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="sphynx",
    version="1.0.0",
    author="Servais1983",
    author_email="",  # À compléter
    description="Outil de collecte DFIR pour l'analyse forensique numérique",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/servais1983/sphynx",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sphynx=kali_dfir_gui:main",
            "sphynx-cli=dfir_remote:main",
        ],
    },
)