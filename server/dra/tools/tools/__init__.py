"""Concrete tool implementations.

All tools are registered on import via ``@tool(...)``.  Importing this
package imports every tool module so the registry is complete even when
a caller only imports a single submodule (e.g. ``analyze_pe``).

Every tool returns a dict; the gateway persists it verbatim.  Tools that
need a file path receive one in their parameters and never execute the
target.

Static-analysis tools:
  * ``analyze_pe``            -- pefile-based PE parsing
  * ``static_strings``        -- printable ASCII/UTF-16LE extraction
  * ``ioctl_extract``         -- capstone DriverEntry / IOCTL analysis
  * ``attack_surface_extract``-- facts -> attack surface items
  * ``poc_generate``          -- IOCTL PoC source generation (source only)
  * ``mock_lab``              -- lab tools backed by the provider factory
"""

# Registration side effects (order is not significant).
from . import analyze_pe  # noqa: F401,E402
from . import static_strings  # noqa: F401,E402
from . import ioctl_extract  # noqa: F401,E402
from . import attack_surface_extract  # noqa: F401,E402
from . import poc_generate  # noqa: F401,E402
from . import mock_lab  # noqa: F401,E402

__all__ = [
    "analyze_pe",
    "static_strings",
    "ioctl_extract",
    "attack_surface_extract",
    "poc_generate",
    "mock_lab",
]
