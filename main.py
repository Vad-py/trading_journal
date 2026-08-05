import os
import shutil
import hmac
import hashlib
import time
import requests
from fastapi import FastAPI, Request, Form, File, UploadFile, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from passlib.context import CryptContext

import models
from database import engine, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

os.makedirs("static/uploads", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_bybit_keys(api_key: str, api_secret: str) -> bool:
    """ Настоящая валидация ключей через REST API Bybit """
    url = "https://api.bybit.com/v5/account/wallet-balance"
    timestamp = str(int(time.time() * 1000))
    recv_window = "5000"
    queryString = "accountType=UNIFIED"
    
    param_str = timestamp + api_key + recv_window + queryString
    signature = hmac.new(bytes(api_secret, "utf-8"), param_str.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "X-BAPI-API-KEY": api_key,
        "X-BAPI-SIGN": signature,
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
    }

    try:
        response = requests.get(f"{url}?{queryString}", headers=headers, timeout=5)
        res_data = response.json()
        return res_data.get("retCode") == 0
    except Exception:
        return False

@app.get("/", response_class=HTMLResponse)
def show_register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.post("/register", response_class=HTMLResponse)
async def register_user(
    request: Request,
    name: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    avatar: UploadFile = File(None),
    db: Session = Depends(get_db)
):
    if not name.strip() or not username.strip() or not password.strip():
        return templates.TemplateResponse(
            request=request, name="register.html",
            context={"error": "Ошибка: Заполните все поля!", "name": name, "username": username}
        )

    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if existing_user:
        return templates.TemplateResponse(
            request=request, name="register.html",
            context={"error": "Ошибка: Этот логин занят.", "name": name, "username": username}
        )

    avatar_url = None
    if avatar and avatar.filename:
        file_location = f"static/uploads/{username}_{avatar.filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(avatar.file, buffer)
        avatar_url = f"/{file_location}"

    hashed_pwd = pwd_context.hash(password)
    new_user = models.User(name=name, username=username, hashed_password=hashed_pwd, avatar_url=avatar_url)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": new_user})

# --- ЭНДПОИНТЫ ДЛЯ РАБОТЫ С API КЛЮЧАМИ ---

@app.post("/api/save-keys")
async def save_api_keys(
    user_id: int = Form(...),
    platform: str = Form(...),
    api_key: str = Form(...),
    api_secret: str = Form(...),
    db: Session = Depends(get_db)
):
    # Валидация реального Bybit API
    if platform.lower() == "bybit":
        is_valid = verify_bybit_keys(api_key, api_secret)
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Ошибка: Биржа Bybit отклонила ключи! Перепутаны местами или неверные данные."}
            )
    else:
        # Для базовой проверки остальных сервисов на этапе теста
        if len(api_key) < 12 or len(api_secret) < 12:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Ошибка: Неверная длина ключей для платформы."}
            )

    # Сохраняем или обновляем ключ в базе
    existing = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id, models.ApiKey.platform == platform).first()
    if existing:
        existing.api_key = api_key
        existing.api_secret = api_secret
    else:
        new_key = models.ApiKey(user_id=user_id, platform=platform, api_key=api_key, api_secret=api_secret)
        db.add(new_key)
    
    db.commit()
    return {"success": True, "message": f"Ключи {platform} успешно верифицированы и привязаны!"}

@app.post("/api/delete-keys")
async def delete_api_keys(
    user_id: int = Form(...),
    platform: str = Form(...),
    db: Session = Depends(get_db)
):
    key_entry = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id, models.ApiKey.platform == platform).first()
    if key_entry:
        db.delete(key_entry)
        db.commit()
    return {"success": True}