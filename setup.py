import os
from setuptools import setup, find_packages

# ==============================================================================
# YOMI TRIAGE SYSTEM: V 2.0 - Production Deployment Configuration
# Purpose: Binds the microservices into a single system-wide executable.
#          - Dependency Pinning (==): Defeats Supply Chain / Confusion Attacks.
#          - Strictly specifies Python 3.10+ for modern type hinting support.
#          - Global Console Script: Enables 'yomi-triage' execution anywhere.
# ==============================================================================

setup(
    name="yomi-triage",
    version="1.0.0",
    description="KuroTech Autonomous DFIR Engine",
    author="KuroTech",
    # Ensures all sub-modules are packaged correctly to prevent ModuleNotFoundError
    packages=find_packages(
        include=["yomi_core", "yomi_engine", "yomi_audit", "yomi_data", "yomi_mcp"]
    ),
    include_package_data=True,
    install_requires=[
        "rich==13.7.1",
        "requests==2.31.0",
        "fpdf==1.7.2",
        "psutil==5.9.8",  # Core OS Telemetry
        "setproctitle==1.3.3",  # Required for Ghost Protocol Deep OS Camouflage
        "boto3==1.34.68",  # Required for AWS KMS integration
    ],
    entry_points={
        "console_scripts": [
            # Binds the terminal command 'yomi-triage' to the CLI entry point
            "yomi-triage=yomi_core.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
)
