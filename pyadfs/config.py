from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    adfs_base_url: Optional[str] = None
    adfs_client_id: Optional[str] = None
    adfs_client_secret: Optional[str] = None
    adfs_audience: Optional[str] = None


settings = Settings()
