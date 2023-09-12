import uuid

from fastapi import FastAPI, Depends, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import db
import schemas
import models

models.Base.metadata.create_all(bind=db.engine)

app = FastAPI(debug=True)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.post("/api", status_code=status.HTTP_201_CREATED, response_model=schemas.User)
async def create_user(user: schemas.UserCreate, _db: Session = Depends(db.get_db)):
    new_user = models.User(**user.model_dump())
    _db.add(new_user)
    _db.commit()
    _db.refresh(new_user)
    return new_user


@app.get("/api/{user_id}", status_code=status.HTTP_200_OK, response_model=schemas.User)
async def get_user(user_id: uuid.UUID, _db: Session = Depends(db.get_db)):
    user = _db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} does not exist"
        )
    return user


@app.put("/api/{user_id}", status_code=status.HTTP_201_CREATED, response_model=schemas.User)
async def update_user(user_id: uuid.UUID, userdetails: schemas.UserCreate, _db: Session = Depends(db.get_db)):
    user = _db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} does not exist"
        )
    user.name = userdetails.name
    _db.commit()
    _db.refresh(user)
    return user


@app.delete("/api/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: uuid.UUID, _db: Session = Depends(db.get_db)):
    user = _db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        _db.delete(user)
        _db.commit()
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} does not exist"
        )
