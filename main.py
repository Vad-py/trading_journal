import os
import shutil
from fastapi import FastAPI, Request, Form, File, UploadFile, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from passlib.context import CryptContext

import models
from database import engine, get_db

# Создаем таблицы в БД при старте
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Папка для сохранения заливов (аватарок)
os.makedirs("static/uploads", exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Хеширование паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.get("/", response_class=HTMLResponse)
def show_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
async def register_user(
    request: Request,
    name: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    avatar: UploadFile = File(None),
    db: Session = Depends(get_db)
):
    # 1. Проверка пустых полей
    if not name.strip() or not username.strip() or not password.strip():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Ошибка: Заполните все обязательные поля (Имя, Логин, Пароль)!",
            "name": name,
            "username": username
        })

    # 2. Проверка уникальности логина
    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Ошибка: Этот логин уже занят. Придумайте другой.",
            "name": name,
            "username": username
        })

    # 3. Сохранение аватарки
    avatar_url = None
    if avatar and avatar.filename:
        file_location = f"static/uploads/{username}_{avatar.filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(avatar.file, buffer)
        avatar_url = f"/{file_location}"

    # 4. Запись пользователя в базу данных
    hashed_pwd = pwd_context.hash(password)
    new_user = models.User(
        name=name,
        username=username,
        hashed_password=hashed_pwd,
        avatar_url=avatar_url
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # 5. Переход на главную страницу
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": new_user})