from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models
from app.db.database import engine
from app.routers import auths, notifications, organizations, transactions, users


models.Base.metadata.create_all(bind=engine)


app = FastAPI(debug=True)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


app.include_router(auths.router)
app.include_router(notifications.router)
app.include_router(transactions.router)
app.include_router(users.router)
app.include_router(organizations.router)


@app.get("/")
async def root():
    return {"message": "Welcome to Free Food App!"}

