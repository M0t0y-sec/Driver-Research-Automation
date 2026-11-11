
from pydantic import BaseModel, Field


class TargetInfo(BaseModel):
    id: str
    project_id: str
    name: str
    sha256: str
    size: int
    file_type: str = "unknown"  # e.g. "pe32+", "pe32", "elf", "raw"
    submitted_at: str
    authorized_use: bool = False
    authorization_ref: str | None = None
    tags: list[str] = Field(default_factory=list)


class EnvironmentInfo(BaseModel):
    id: str
    name: str
    os_build: str
    patch_level: str
    driver_signing: str  # "test_signing" | "production" | "unknown"
    security_product: str | None = None
    snapshot_id: str | None = None
    vm_fingerprint: str | None = None
