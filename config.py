import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv('.env')


class Settings:
    db_hostname = os.environ.get('DB_HOSTNAME')
    db_port = os.environ.get('DB_PORT')
    db_password = os.environ.get('DB_PASSWORD')
    db_username = os.environ.get('DB_USERNAME')
    db_name = os.environ.get('DB_NAME')


settings = Settings()
