from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from .database import engine, Base, SessionLocal
from . import models, schemas
from .auth import hash_password, verify_password, create_access_token

app = FastAPI()

Base.metadata.create_all(bind=engine)

# Dependencia DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email ya registrado")

    hashed = hash_password(user.password)
    new_user = models.User(email=user.email, password=hashed)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "Usuario creado correctamente"}

@app.post("/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()

    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Credenciales incorrectas")

    token = create_access_token(data={"sub": db_user.email})

    return {"access_token": token, "token_type": "bearer"}