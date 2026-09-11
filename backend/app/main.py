from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import settings
from app.db.models import Base  # noqa: F401 — registers all models
from app.db.session import engine


from sqlalchemy import text


def _run_migrations():
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name='findings' AND column_name='triage_status'
                    ) THEN
                        ALTER TABLE findings ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'open';
                        ALTER TABLE findings ADD COLUMN triage_notes TEXT;
                        ALTER TABLE findings ADD COLUMN triaged_by TEXT;
                        ALTER TABLE findings ADD COLUMN triaged_at TIMESTAMPTZ;
                    END IF;
                END $$;
                """
            )
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)  # matches db/schema.sql
    try:
        _run_migrations()
    except Exception:
        pass  # Non-fatal if sqlite or already migrated
    yield


app = FastAPI(title="Dependency Risk Dashboard", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(router)


@app.get("/healthz")
@app.get("/")
def health_check():
    return {"status": "ok"}

