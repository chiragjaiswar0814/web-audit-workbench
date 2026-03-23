from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _db_path() -> str:
    base = Path(__file__).resolve().parents[1]
    instance_dir = base / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    return str(instance_dir / "workbench.sqlite3")


ENGINE = create_engine(
    f"sqlite:///{_db_path()}",
    connect_args={"check_same_thread": False},
    future=True,
)

SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False, future=True)


@contextmanager
def db_session():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
