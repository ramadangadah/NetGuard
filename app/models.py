from datetime import datetime
from typing import Optional

from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    is_admin: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AllowlistEntry(SQLModel, table=True):
    """CIDR ranges the admin has authorized for scanning."""
    id: Optional[int] = Field(default=None, primary_key=True)
    cidr: str = Field(index=True, unique=True)
    label: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanJob(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target: str  # CIDR / host / range as submitted
    scan_type: str  # "discovery" | "vuln"
    status: str = Field(default="queued")  # queued|running|done|error|cancelled
    created_by: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    hosts_found: int = 0
    findings_found: int = 0


class Host(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ip: str = Field(index=True)
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    scan_job_id: Optional[int] = Field(default=None, foreign_key="scanjob.id")


class Port(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    scan_job_id: Optional[int] = Field(default=None, foreign_key="scanjob.id")
    template_id: str
    name: str
    severity: str  # info|low|medium|high|critical
    description: Optional[str] = None
    matched_at: Optional[str] = None
    reference: Optional[str] = None
    cve_id: Optional[str] = None
    found_at: datetime = Field(default_factory=datetime.utcnow)
