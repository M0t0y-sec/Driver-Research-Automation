"""FastAPI / Starlette compatibility shim.

FastAPI 0.124 + starlette 1.6 mismatch: FastAPI's APIRouter still
references `on_startup` / `on_shutdown` (both in the Router
super-call and on `self.on_startup`), while modern starlette removed
both. We patch the Starlette Router so it (a) accepts the legacy
kwargs, and (b) sets the corresponding attributes on `self`, so
FastAPI's `include_router` keeps working.

Import this BEFORE constructing any `fastapi.APIRouter`.
"""

import starlette.routing as _sr

if not getattr(_sr.Router.__init__, "_dra_patched", False):
    _orig = _sr.Router.__init__

    def _patched(self, *args, **kwargs):
        on_startup = kwargs.pop("on_startup", None)
        on_shutdown = kwargs.pop("on_shutdown", None)
        result = _orig(self, *args, **kwargs)
        # FastAPI reads these attributes on the instance.
        self.on_startup = list(on_startup or [])
        self.on_shutdown = list(on_shutdown or [])
        return result

    _patched._dra_patched = True  # type: ignore[attr-defined]
    _sr.Router.__init__ = _patched  # type: ignore[assignment]
