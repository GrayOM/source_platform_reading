from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sss_platform",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.workers.scan_worker",
        "app.workers.analysis_worker",
        "app.workers.report_worker",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.workers.scan_worker.*": {"queue": "crawl"},
        "app.workers.analysis_worker.*": {"queue": "analysis"},
        "app.workers.report_worker.*": {"queue": "reports"},
        "app.workers.scan_worker.run_browser_auth": {"queue": "auth"},
    },
    beat_schedule={},
)
