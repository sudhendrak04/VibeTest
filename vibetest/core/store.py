"""SQLite persistence. Scan once, re-render reports without re-scanning."""
from __future__ import annotations

from datetime import datetime

from sqlmodel import Field, Session, SQLModel, create_engine, select

from ..schemas.scan import ScanResult


class ScanRow(SQLModel, table=True):
    scan_id: str = Field(primary_key=True)
    target_url: str
    started_at: datetime
    artifact_json: str


class FindingRow(SQLModel, table=True):
    finding_id: str = Field(primary_key=True)
    scan_id: str = Field(index=True)
    detector_id: str
    severity: str
    title: str
    finding_json: str


class Store:
    def __init__(self, path: str = "vibetest.db"):
        self.engine = create_engine(f"sqlite:///{path}")
        SQLModel.metadata.create_all(self.engine)

    def save_scan(self, result: ScanResult) -> None:
        with Session(self.engine) as session:
            session.add(
                ScanRow(
                    scan_id=result.scan_id,
                    target_url=result.target_url,
                    started_at=result.started_at,
                    artifact_json=result.artifact.model_dump_json(),
                )
            )
            for f in result.findings:
                session.add(
                    FindingRow(
                        finding_id=f.finding_id,
                        scan_id=result.scan_id,
                        detector_id=f.detector_id,
                        severity=f.severity.value,
                        title=f.title,
                        finding_json=f.model_dump_json(),
                    )
                )
            session.commit()

    def get_scan(self, scan_id: str) -> ScanRow | None:
        with Session(self.engine) as session:
            return session.get(ScanRow, scan_id)

    def findings_for(self, scan_id: str) -> list[FindingRow]:
        with Session(self.engine) as session:
            return list(session.exec(select(FindingRow).where(FindingRow.scan_id == scan_id)).all())

    def list_scans(self) -> list[ScanRow]:
        with Session(self.engine) as session:
            return list(session.exec(select(ScanRow).order_by(ScanRow.started_at.desc())).all())
