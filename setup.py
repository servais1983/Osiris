"""
Configuration du package Osiris.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="osiris",
    version="0.1.0",
    author="Osiris Team",
    author_email="contact@osiris-dfir.com",
    description="Plateforme DFIR de Nouvelle Génération",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/osiris-dfir/osiris",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "osiris-hive=osiris.hive.server:main",
            "osiris-agent=osiris.agent.client:main",
        ],
    },
) 