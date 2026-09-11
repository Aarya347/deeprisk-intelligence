from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Repository(Base):
    __tablename__ = "repositories"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    github_full_name: Mapped[str] = mapped_column(Text, unique=True)
    default_branch: Mapped[str | None] = mapped_column(Text)
    primary_language: Mapped[str | None] = mapped_column(Text)
    exposure_tier: Mapped[str] = mapped_column(String(16), default="unknown")
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)
    last_scan_id: Mapped[int | None] = mapped_column(BigInteger)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(16), default="running")
    error: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Dependency(Base):
    __tablename__ = "dependencies"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    ecosystem: Mapped[str] = mapped_column(String(16))            # 'PyPI' | 'npm'
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text, default="")
    version_source: Mapped[str] = mapped_column(String(16), default="none")
    raw_specifier: Mapped[str | None] = mapped_column(Text)
    is_direct: Mapped[bool] = mapped_column(Boolean, default=True)
    is_dev: Mapped[bool] = mapped_column(Boolean, default=False)
    source_file: Mapped[str] = mapped_column(Text)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    osv_id: Mapped[str] = mapped_column(Text, unique=True)
    cve_id: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(16))
    fixed_versions: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    raw: Mapped[dict | None] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependencies.id", ondelete="CASCADE"))
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"))
    reachable: Mapped[bool | None] = mapped_column(Boolean)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    risk_score: Mapped[float] = mapped_column(Numeric(4, 2))
    risk_tier: Mapped[str] = mapped_column(String(2))
    rationale: Mapped[list] = mapped_column(JSONB, default=list)
    triage_status: Mapped[str] = mapped_column(String(32), default="open")
    triage_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    triaged_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
