"""
DWE Iceberg Catalog — Pulumi entry point.
Reads cloud_provider from dwe-hydration.yaml and delegates to the provider module.
"""

import yaml
from pathlib import Path

_dwe = yaml.safe_load((Path(__file__).parent / "dwe-hydration.yaml").read_text())
cloud_provider = _dwe.get("cloud_provider", "azure")

if cloud_provider == "azure":
    import _azure  # noqa: F401
else:
    import _aws  # noqa: F401
