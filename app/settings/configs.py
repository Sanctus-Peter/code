import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    db_hostname: str = os.environ.get('DB_HOSTNAME')
    db_port: int = os.environ.get('DB_PORT')
    db_password: str = os.environ.get('DB_PASSWORD')
    db_username: str = os.environ.get('DB_USERNAME')
    db_name: str = os.environ.get('DB_NAME')
    secret_key: str = os.environ.get('SECRET_KEY')
    algorithm: str = os.environ.get('ALGORITHM')
    access_tok_expire_minutes: int = os.environ.get('ACCESS_TOK_EXPIRE_MINUTES')
    api_key: str = os.environ.get('SMS_API_KEY')
    api_secret: str = os.environ.get('SMS_API_SECRET')
    OTP_INTERVAL: int = os.environ.get('OTP_INTERVAL')


settings = Settings()
