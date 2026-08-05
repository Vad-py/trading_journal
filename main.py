import os
import shutil
import hmac
import hashlib
import time
import requests
import bcrypt
from fastapi import FastAPI, Request, Form, File, UploadFile, Depends
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

# ============ UTILS ============

def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def make_bybit_signature(api_secret: str, payload: str) -> str:
    """Создаёт HMAC-SHA256 подпись для Bybit."""
    return hmac.new(
        bytes(api_secret, "utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def verify_bybit_keys(api_key: str, api_secret: str) -> bool:
    url = "https://api.bybit.com/v5/account/wallet-balance"
    timestamp = str(int(time.time() * 1000))
    recv_window = "5000"
    queryString = "accountType=UNIFIED"
    
    param_str = timestamp + api_key + recv_window + queryString
    signature = make_bybit_signature(api_secret, param_str)

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

def bybit_request(api_key: str, api_secret: str, endpoint: str, query_string: str = ""):
    """Универсальный метод для подписанных запросов к Bybit."""
    timestamp = str(int(time.time() * 1000))
    recv_window = "5000"
    
    param_str = timestamp + api_key + recv_window + query_string
    signature = make_bybit_signature(api_secret, param_str)

    headers = {
        "X-BAPI-API-KEY": api_key,
        "X-BAPI-SIGN": signature,
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": recv_window,
    }

    url = f"https://api.bybit.com{endpoint}"
    if query_string:
        url += f"?{query_string}"
    
    response = requests.get(url, headers=headers, timeout=10)
    return response.json()

# ============ PAGES ============

@app.get("/", response_class=HTMLResponse)
def show_register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.get("/dashboard/{user_id}", response_class=HTMLResponse)
def show_dashboard(request: Request, user_id: int, db: Session = Depends(get_db)):
    """Прямой доступ к дашборду по user_id."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return templates.TemplateResponse(request=request, name="register.html", context={"error": "Пользователь не найден"})
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": user})

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

# ============ API KEYS ============

@app.post("/api/save-keys")
async def save_api_keys(
    user_id: int = Form(...),
    platform: str = Form(...),
    api_key: str = Form(...),
    api_secret: str = Form(...),
    db: Session = Depends(get_db)
):
    if platform.lower() == "bybit":
        is_valid = verify_bybit_keys(api_key, api_secret)
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Ошибка: Биржа Bybit отклонила ключи!"}
            )
    else:
        if len(api_key) < 12 or len(api_secret) < 12:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Ошибка: Неверная длина ключей."}
            )

    existing = db.query(models.ApiKey).filter(
        models.ApiKey.user_id == user_id, 
        models.ApiKey.platform == platform
    ).first()
    
    if existing:
        existing.api_key = api_key
        existing.api_secret = api_secret
    else:
        new_key = models.ApiKey(user_id=user_id, platform=platform, api_key=api_key, api_secret=api_secret)
        db.add(new_key)
    
    db.commit()
    return {"success": True, "message": f"Ключи {platform} верифицированы!"}

@app.post("/api/delete-keys")
async def delete_api_keys(
    user_id: int = Form(...),
    platform: str = Form(...),
    db: Session = Depends(get_db)
):
    key_entry = db.query(models.ApiKey).filter(
        models.ApiKey.user_id == user_id, 
        models.ApiKey.platform == platform
    ).first()
    if key_entry:
        db.delete(key_entry)
        db.commit()
    return {"success": True}

# ============ TRADES (DATABASE) ============

@app.get("/api/trades/{user_id}")
async def get_user_trades(user_id: int, db: Session = Depends(get_db)):
    """Возвращает все сохранённые сделки пользователя из БД."""
    trades = db.query(models.Trade).filter(models.Trade.user_id == user_id).order_by(models.Trade.exit_time.desc()).all()
    
    result = []
    for t in trades:
        entry_dt = time.strftime('%d %b %H:%M', time.localtime(t.entry_time)) if t.entry_time else "-"
        exit_dt = time.strftime('%d %b %H:%M', time.localtime(t.exit_time)) if t.exit_time else "-"
        
        pnl_sign = "+" if t.pnl >= 0 else ""
        pnl_pct_sign = "+" if t.pnl_percent >= 0 else ""
        
        result.append({
            "id": t.id,
            "order_id": t.order_id,
            "ticker": t.symbol,
            "exchange": t.platform.lower(),
            "entry": entry_dt,
            "exit": exit_dt,
            "side": "Buy" if t.side.lower() == "buy" else "Sell",
            "pnlPercent": f"{pnl_pct_sign}{t.pnl_percent:.2f}%",
            "profit": f"{pnl_sign}{t.pnl:.2f} $",
            "revenue": f"{t.qty * t.exit_price:.2f} $",
            "commission": f"{t.commission:.2f} $",
            "volume": f"{t.qty * t.entry_price:.1f} $",
            "entryPrice": t.entry_price,
            "exitPrice": t.exit_price,
            "entryTime": t.entry_time,
            "exitTime": t.exit_time,
            "qty": t.qty
        })
    
    return {"status": "success", "trades": result}

# ============ BYBIT SYNC (CLOSED-PNL) ============

@app.get("/api/sync-trades/{user_id}")
async def sync_user_trades(user_id: int, db: Session = Depends(get_db)):
    key_entry = db.query(models.ApiKey).filter(
        models.ApiKey.user_id == user_id, 
        models.ApiKey.platform == "Bybit"
    ).first()
    
    if not key_entry:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Сначала подключите API-ключи Bybit!"}
        )
    
    api_key = key_entry.api_key
    api_secret = key_entry.api_secret
    
    # Используем /v5/position/closed-pnl — именно закрытые позиции с реальным PNL
    query_string = "category=linear&limit=50"
    res_data = bybit_request(api_key, api_secret, "/v5/position/closed-pnl", query_string)
    
    if res_data.get("retCode") != 0:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": f"Ошибка биржи: {res_data.get('retMsg')}"}
        )
    
    raw_list = res_data.get("result", {}).get("list", [])
    synced_count = 0
    
    for item in raw_list:
        order_id = item.get("orderId")
        if not order_id:
            continue
            
        # Проверяем, есть ли уже такая сделка в БД
        existing = db.query(models.Trade).filter(
            models.Trade.user_id == user_id,
            models.Trade.order_id == order_id
        ).first()
        
        symbol = item.get("symbol", "")
        side = item.get("side", "Buy")
        qty = float(item.get("qty", 0))
        avg_entry = float(item.get("avgEntryPrice", 0))
        avg_exit = float(item.get("avgExitPrice", 0))
        closed_pnl = float(item.get("closedPnl", 0))
        cum_entry_value = float(item.get("cumEntryValue", 0))
        open_fee = float(item.get("openFee", 0))
        close_fee = float(item.get("closeFee", 0))
        
        # Расчёт PNL %
        pnl_percent = 0.0
        if cum_entry_value > 0:
            pnl_percent = (closed_pnl / cum_entry_value) * 100
        
        # Временные метки (мс → сек)
        entry_ts = int(item.get("createdTime", 0)) // 1000
        exit_ts = int(item.get("updatedTime", 0)) // 1000
        
        if existing:
            # Обновляем существующую сделку
            existing.exit_price = avg_exit
            existing.pnl = closed_pnl
            existing.pnl_percent = pnl_percent
            existing.close_fee = close_fee
            existing.commission = open_fee + close_fee
            existing.exit_time = exit_ts
        else:
            # Создаём новую сделку
            new_trade = models.Trade(
                user_id=user_id,
                order_id=order_id,
                platform="Bybit",
                symbol=symbol,
                side=side,
                entry_price=avg_entry,
                exit_price=avg_exit,
                qty=qty,
                pnl=closed_pnl,
                pnl_percent=pnl_percent,
                open_fee=open_fee,
                close_fee=close_fee,
                commission=open_fee + close_fee,
                entry_time=entry_ts,
                exit_time=exit_ts
            )
            db.add(new_trade)
            synced_count += 1
    
    db.commit()
    
    # Возвращаем актуальный список из БД
    return await get_user_trades(user_id, db)

# ============ KLINES (PUBLIC) ============

@app.get("/api/kline")
async def get_bybit_kline(symbol: str, interval: str = "1"):
    url = "https://api.bybit.com/v5/market/kline"
    params = {
        "category": "linear",
        "symbol": symbol,
        "interval": interval,
        "limit": 200
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        res_data = response.json()
        if res_data.get("retCode") != 0:
            return JSONResponse(status_code=400, content={"error": res_data.get("retMsg")})
        
        raw_list = res_data.get("result", {}).get("list", [])
        # Bybit выдаёт от новых к старым — разворачиваем
        raw_list.reverse()
        
        candles = []
        for item in raw_list:
            candles.append({
                "time": int(item[0]) // 1000,
                "open": float(item[1]),
                "high": float(item[2]),
                "low": float(item[3]),
                "close": float(item[4]),
                "volume": float(item[5])
            })
        return {"candles": candles}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})