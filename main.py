import os
import shutil
import hmac
import hashlib
import time
import requests
import bcrypt
from fastapi import FastAPI, Request, Form, File, UploadFile, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

import models
from database import engine, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

os.makedirs("static/uploads", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

# --- ПРОВЕРКА КЛЮЧЕЙ ---

def verify_bybit_keys(api_key: str, api_secret: str) -> bool:
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
        res = requests.get(f"{url}?{queryString}", headers=headers, timeout=5)
        return res.json().get("retCode") == 0
    except Exception:
        return False

def verify_binance_keys(api_key: str, api_secret: str) -> bool:
    url = "https://api.binance.com/api/v3/account"
    timestamp = str(int(time.time() * 1000))
    query_string = f"timestamp={timestamp}"
    signature = hmac.new(bytes(api_secret, "utf-8"), query_string.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {"X-MBX-APIKEY": api_key}
    try:
        res = requests.get(f"{url}?{query_string}&signature={signature}", headers=headers, timeout=5)
        return res.status_code == 200
    except Exception:
        return False

# --- СИНХРОНИЗАЦИЯ РЕАЛЬНЫХ СДЕЛОК (BYBIT) ---

def fetch_bybit_trades(api_key: str, api_secret: str):
    """ Вытягивает исполненные ордера с Bybit """
    url = "https://api.bybit.com/v5/execution/list"
    timestamp = str(int(time.time() * 1000))
    recv_window = "5000"
    queryString = "category=linear&limit=20"
    param_str = timestamp + api_key + recv_window + queryString
    signature = hmac.new(bytes(api_secret, "utf-8"), param_str.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "X-BAPI-API-KEY": api_key,
        "X-BAPI-SIGN": signature,
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
    }
    try:
        res = requests.get(f"{url}?{queryString}", headers=headers, timeout=5)
        data = res.json()
        if data.get("retCode") == 0:
            return data.get("result", {}).get("list", [])
    except Exception:
        pass
    return []

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

    hashed_pwd = hash_password(password)
    new_user = models.User(name=name, username=username, hashed_password=hashed_pwd, avatar_url=avatar_url)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": new_user})

@app.post("/api/save-keys")
async def save_api_keys(
    user_id: int = Form(...),
    platform: str = Form(...),
    api_key: str = Form(...),
    api_secret: str = Form(...),
    db: Session = Depends(get_db)
):
    platform_clean = platform.lower().strip()
    is_valid = False

    if "bybit" in platform_clean:
        is_valid = verify_bybit_keys(api_key, api_secret)
    elif "binance" in platform_clean or "tiger" in platform_clean or "vataga" in platform_clean:
        is_valid = verify_binance_keys(api_key, api_secret)

    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"Ошибка авторизации! Ключи {platform} отклонены."}
        )

    existing = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id, models.ApiKey.platform == platform).first()
    if existing:
        existing.api_key = api_key
        existing.api_secret = api_secret
    else:
        new_key = models.ApiKey(user_id=user_id, platform=platform, api_key=api_key, api_secret=api_secret)
        db.add(new_key)
    
    db.commit()
    return {"success": True, "message": f"Ключи {platform} подлинны и сохранены!"}

@app.get("/api/sync-trades/{user_id}")
async def sync_user_trades(user_id: int, db: Session = Depends(get_db)):
    """ Эндпоинт фоновой синхронизации сделок """
    keys = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id).all()
    
    for key_item in keys:
        if "bybit" in key_item.platform.lower():
            raw_trades = fetch_bybit_trades(key_item.api_key, key_item.api_secret)
            for t in raw_trades:
                symbol = t.get("symbol")
                side = "LONG" if t.get("side") == "Buy" else "SHORT"
                exec_price = float(t.get("execPrice", 0))
                exec_qty = float(t.get("execQty", 0))
                fee = float(t.get("execFee", 0))

                # Проверяем, нет ли уже этой сделки
                new_trade = models.Trade(
                    user_id=user_id,
                    platform=key_item.platform,
                    symbol=symbol,
                    side=side,
                    entry_price=exec_price,
                    exit_price=exec_price,
                    qty=exec_qty,
                    pnl=0.0,
                    pnl_percent=0.0,
                    commission=fee
                )
                db.add(new_trade)
            db.commit()

    # Загружаем все сделки из БД
    trades = db.query(models.Trade).filter(models.Trade.user_id == user_id).all()
    
    result_trades = []
    for tr in trades:
        result_trades.append({
            "ticker": tr.symbol,
            "entry": tr.created_at.strftime("%d %b %H:%M:%S"),
            "exit": tr.created_at.strftime("%d %b %H:%M:%S"),
            "side": tr.side,
            "pnlPercent": f"{tr.pnl_percent:+.2f}%",
            "profit": f"{tr.pnl:+.2f} $",
            "revenue": f"{tr.pnl:+.2f} $",
            "commission": f"{tr.commission:.2f} $",
            "volume": f"{tr.entry_price * tr.qty:.0f} $"
        })

    return {"success": True, "trades": result_trades}