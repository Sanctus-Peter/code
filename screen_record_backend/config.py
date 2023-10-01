import os
from dotenv import load_dotenv

load_dotenv()


def get_db_details():

    db_data = {
        "dbname": os.environ.get("DB_NAME"),
        "username": os.environ.get("DB_USER"),
        "password": os.environ.get("DB_PASSWORD"),
        "host": os.environ.get("DB_HOST"),
        "port": os.environ.get("DB_PORT"),
    }
    return db_data
