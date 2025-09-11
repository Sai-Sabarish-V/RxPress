import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_PORT = int(os.environ.get("DB_PORT", "3306"))
    DB_USER = os.environ.get("DB_USER", "root")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "admin1234")
    DB_NAME = os.environ.get("DB_NAME", "RxPress")

    # Optional SSL CA for cloud DBs. Leave empty for local MySQL.
    SSL_CA = os.environ.get("SSL_CA", "")

    # App settings
    SESSION_COOKIE_NAME = "rxpress_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PREFERRED_URL_SCHEME = "https"


def get_database_config() -> dict:
    cfg = {
        "host": Config.DB_HOST,
        "user": Config.DB_USER,
        "password": Config.DB_PASSWORD,
        "database": Config.DB_NAME,
    }
    # Include port if set
    if Config.DB_PORT:
        cfg["port"] = Config.DB_PORT
    # Include SSL CA only if provided
    if Config.SSL_CA:
        cfg["ssl_ca"] = Config.SSL_CA
    return cfg
