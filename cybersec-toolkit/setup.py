#!/usr/bin/env python3
"""
Setup script for Cybersecurity Toolkit.
"""
from setuptools import setup, find_packages

with open("VERSION", "r") as version_file:
    version = version_file.read().strip()

with open("README.md", "r", encoding="utf-8") as readme_file:
    long_description = readme_file.read()

setup(
    name="cybersec-toolkit",
    version=version,
    author="Security Team",
    author_email="security@example.com",
    description="A comprehensive cybersecurity toolkit for Linux systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/cybersec-toolkit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=6.0",
        "colorama>=0.4.6",
        "click>=8.1.0",
        "jinja2>=3.1.0",
        "requests>=2.31.0",
        "docker>=6.1.0",
    ],
    entry_points={
        "console_scripts": [
            "cybersec=cybersec.cli.main:main",
        ],
    },
)