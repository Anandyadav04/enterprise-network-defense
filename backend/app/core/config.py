"""
backend/app/core/config.py
───────────────────────────
Application configuration loaded from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # FastAPI
    DEBUG: bool = False
    SECRET_KEY: str = "change-this-in-production"
    CORS_ORIGINS: List[str] = ["http://localhost:5601", "http://localhost:3000"]

    # PostgreSQL
    DATABASE_URL: str = "postgresql+asyncpg://netadmin:changeme@localhost:5432/netdefense"

    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"
    ES_SECURITY_INDEX: str = "security-events"

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "kafka:9092"

    # Threat Intelligence
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # Notifications
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_RECIPIENT: str = ""
    SLACK_WEBHOOK_URL: str = ""

    # IPS
    IPS_ENABLED: bool = False
    PFSENSE_HOST: str = ""
    PFSENSE_API_KEY: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
