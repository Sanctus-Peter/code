from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(debug=True)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/api/")
async def root(slack_name: str, track: str):
    try:
        # Current day and time
        current_day = datetime.now().strftime("%A")
        utc_time = datetime.utcnow()

        # GitHub URLs
        github_file_url = "https://github.com/Sanctus-Peter/HNG-x/blob/main/HNG-X-1/fastapi/main.py"
        github_repo_url = "https://github.com/Sanctus-Peter/HNG-x/tree/main/HNG-X-1/"

        # Response JSON
        response = {
            "slack_name": slack_name,
            "current_day": current_day,
            "utc_time": utc_time,
            "track": track,
            "github_file_url": github_file_url,
            "github_repo_url": github_repo_url,
            "status_code": 200,
        }

        return response

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
