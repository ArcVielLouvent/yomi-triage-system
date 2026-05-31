from setuptools import setup, find_packages

# ==============================================================================
# YOMI TRIAGE SYSTEM: Phase 6.1 - Global Entry Point Configuration
# Purpose: Binds the 28 microservices into a single system-wide executable.
# ==============================================================================

setup(
    name="yomi-triage",
    version="4.0.0",
    description="KuroTech Autonomous DFIR Engine",
    author="KuroTech",
    packages=find_packages(),
    install_requires=["rich", "fpdf", "requests"],
    entry_points={
        "console_scripts": [
            # This magic line creates the terminal command 'yomi-triage'
            "yomi-triage=yomi_core.cli:main",
        ],
    },
)
