import os
import shutil
import hmac
import hashlib
import time
import requests
import bcrypt
import base64
from fastapi import FastAPI, Request, Form, File, UploadFile, Depends, Query
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

def hmac_sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()

# ==================== BYBIT ====================
def verify_bybit_keys(key: str, sec: str) -> bool:
    ts = str(int(time.time() * 1000))
    qs = "accountType=UNIFIED"
    sig = hmac_sign(sec, ts + key + "5000" + qs)
    headers = {"X-BAPI-API-KEY": key, "X-BAPI-SIGN": sig, "X-BAPI-TIMESTAMP": ts, "X-BAPI-RECV-WINDOW": "5000"}
    try:
        r = requests.get(f"https://api.bybit.com/v5/account/wallet-balance?{qs}", headers=headers, timeout=5)
        return r.json().get("retCode") == 0
    except:
        return False

def bybit_req(key, sec, endpoint, qs=""):
    ts = str(int(time.time() * 1000))
    sig = hmac_sign(sec, ts + key + "5000" + qs)
    headers = {"X-BAPI-API-KEY": key, "X-BAPI-SIGN": sig, "X-BAPI-TIMESTAMP": ts, "X-BAPI-RECV-WINDOW": "5000"}
    url = f"https://api.bybit.com{endpoint}" + (f"?{qs}" if qs else "")
    return requests.get(url, headers=headers, timeout=10).json()

def sync_bybit(uid, key, sec, db):
    data = bybit_req(key, sec, "/v5/position/closed-pnl", "category=linear&limit=50")
    if data.get("retCode") != 0:
        return {"status": "error", "message": f"Bybit: {data.get('retMsg')}"}
    cnt = 0
    for item in data.get("result", {}).get("list", []):
        oid = item.get("orderId")
        if not oid: continue
        ex = db.query(models.Trade).filter(models.Trade.user_id == uid, models.Trade.order_id == oid).first()
        sym = item.get("symbol", "")
        side = item.get("side", "Buy")
        qty = float(item.get("qty", 0))
        ent = float(item.get("avgEntryPrice", 0))
        exi = float(item.get("avgExitPrice", 0))
        pnl = float(item.get("closedPnl", 0))
        cev = float(item.get("cumEntryValue", 0))
        of = float(item.get("openFee", 0))
        cf = float(item.get("closeFee", 0))
        pp = (pnl / cev * 100) if cev > 0 else 0
        ets = int(item.get("createdTime", 0)) // 1000
        xts = int(item.get("updatedTime", 0)) // 1000
        if ex:
            ex.exit_price = exi; ex.pnl = pnl; ex.pnl_percent = pp; ex.close_fee = cf; ex.commission = of + cf; ex.exit_time = xts
        else:
            db.add(models.Trade(user_id=uid, order_id=oid, platform="Bybit", symbol=sym, side=side,
                entry_price=ent, exit_price=exi, qty=qty, pnl=pnl, pnl_percent=pp,
                open_fee=of, close_fee=cf, commission=of+cf, entry_time=ets, exit_time=xts))
            cnt += 1
    db.commit()
    return {"status": "success", "count": cnt}

# ==================== BINANCE ====================
def verify_binance_keys(key: str, sec: str) -> bool:
    ts = str(int(time.time() * 1000))
    qs = f"timestamp={ts}"
    sig = hmac_sign(sec, qs)
    headers = {"X-MBX-APIKEY": key}
    try:
        r = requests.get(f"https://fapi.binance.com/fapi/v2/account?{qs}&signature={sig}", headers=headers, timeout=5)
        return r.status_code == 200 and 'totalWalletBalance' in r.json()
    except:
        return False

def sync_binance(uid, key, sec, db):
    ts = str(int(time.time() * 1000))
    qs = f"incomeType=REALIZED_PNL&limit=50&timestamp={ts}"
    sig = hmac_sign(sec, qs)
    headers = {"X-MBX-APIKEY": key}
    r = requests.get(f"https://fapi.binance.com/fapi/v1/income?{qs}&signature={sig}", headers=headers, timeout=10)
    data = r.json()
    if r.status_code != 200:
        return {"status": "error", "message": f"Binance: {data}"}
    cnt = 0
    for item in data:
        tid = f"BNB_{item.get('tranId')}"
        sym = item.get("symbol", "")
        inc = float(item.get("income", 0))
        tms = int(item.get("time", 0)) // 1000
        if db.query(models.Trade).filter(models.Trade.user_id == uid, models.Trade.order_id == tid).first():
            continue
        db.add(models.Trade(user_id=uid, order_id=tid, platform="Binance", symbol=sym,
            side="Buy" if inc >= 0 else "Sell", entry_price=0, exit_price=0, qty=0,
            pnl=inc, pnl_percent=0, commission=0, entry_time=tms, exit_time=tms))
        cnt += 1
    db.commit()
    return {"status": "success", "count": cnt}

# ==================== OKX ====================
def verify_okx_keys(key: str, sec: str, phrase: str) -> bool:
    ts = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
    msg = ts + "GET" + "/api/v5/account/balance"
    sig = base64.b64encode(hmac.new(sec.encode(), msg.encode(), hashlib.sha256).digest()).decode()
    headers = {"OK-ACCESS-KEY": key, "OK-ACCESS-SIGN": sig, "OK-ACCESS-TIMESTAMP": ts, "OK-ACCESS-PASSPHRASE": phrase}
    try:
        r = requests.get("https://www.okx.com/api/v5/account/balance", headers=headers, timeout=5)
        return r.json().get("code") == "0"
    except:
        return False

def sync_okx(uid, key, sec, phrase, db):
    ts = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
    path = "/api/v5/account/positions-history?instType=SWAP"
    sig = base64.b64encode(hmac.new(sec.encode(), (ts + "GET" + path).encode(), hashlib.sha256).digest()).decode()
    headers = {"OK-ACCESS-KEY": key, "OK-ACCESS-SIGN": sig, "OK-ACCESS-TIMESTAMP": ts, "OK-ACCESS-PASSPHRASE": phrase}
    r = requests.get(f"https://www.okx.com{path}", headers=headers, timeout=10)
    data = r.json()
    if data.get("code") != "0":
        return {"status": "error", "message": f"OKX: {data.get('msg')}"}
    cnt = 0
    for item in data.get("data", []):
        pid = item.get("posId")
        if not pid: continue
        ex = db.query(models.Trade).filter(models.Trade.user_id == uid, models.Trade.order_id == pid).first()
        sym = item.get("instId", "")
        side = "Buy" if item.get("posSide") == "long" else "Sell"
        opn = float(item.get("avgOpenPx", 0))
        cls = float(item.get("avgClosePx", 0))
        pnl = float(item.get("pnl", 0))
        pnr = float(item.get("pnlRatio", 0)) * 100
        qty = float(item.get("openMaxPos", 0))
        otm = int(item.get("openTime", "")) // 1000 if item.get("openTime") else None
        ctm = int(item.get("closeTime", "")) // 1000 if item.get("closeTime") else None
        if ex:
            ex.exit_price = cls; ex.pnl = pnl; ex.pnl_percent = pnr; ex.exit_time = ctm
        else:
            db.add(models.Trade(user_id=uid, order_id=pid, platform="OKX", symbol=sym, side=side,
                entry_price=opn, exit_price=cls, qty=qty, pnl=pnl, pnl_percent=pnr,
                entry_time=otm, exit_time=ctm))
            cnt += 1
    db.commit()
    return {"status": "success", "count": cnt}

# ==================== TIGER / VATAGA ====================
def sync_tiger(uid, key, sec, db):
    return {"status": "info", "message": "Tiger Trade: API синхронизация в разработке."}
def sync_vataga(uid, key, sec, db):
    return {"status": "info", "message": "Vataga: API синхронизация в разработке."}

# ==================== PAGES ====================
@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.get("/dashboard/{user_id}", response_class=HTMLResponse)
def dashboard(request: Request, user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return templates.TemplateResponse(request=request, name="register.html", context={"error": "Пользователь не найден"})
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": user})

@app.post("/register", response_class=HTMLResponse)
async def register(request: Request, name: str = Form(""), username: str = Form(""),
                   password: str = Form(""), avatar: UploadFile = File(None), db: Session = Depends(get_db)):
    if not name.strip() or not username.strip() or not password.strip():
        return templates.TemplateResponse(request=request, name="register.html",
            context={"error": "Заполните все поля!", "name": name, "username": username})
    if db.query(models.User).filter(models.User.username == username).first():
        return templates.TemplateResponse(request=request, name="register.html",
            context={"error": "Логин занят.", "name": name, "username": username})
    av = None
    if avatar and avatar.filename:
        path = f"static/uploads/{username}_{avatar.filename}"
        with open(path, "wb") as f: shutil.copyfileobj(avatar.file, f)
        av = f"/{path}"
    u = models.User(name=name, username=username, hashed_password=hash_password(password), avatar_url=av)
    db.add(u); db.commit(); db.refresh(u)
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": u})

# ==================== API KEYS ====================
@app.post("/api/save-keys")
async def save_keys(user_id: int = Form(...), platform: str = Form(...), api_key: str = Form(...),
                    api_secret: str = Form(...), api_passphrase: str = Form(""), db: Session = Depends(get_db)):
    plat = platform.strip()
    if plat == "Bybit" and not verify_bybit_keys(api_key, api_secret):
        return JSONResponse(status_code=400, content={"success": False, "message": "Bybit отклонил ключи!"})
    if plat == "Binance" and not verify_binance_keys(api_key, api_secret):
        return JSONResponse(status_code=400, content={"success": False, "message": "Binance отклонил ключи!"})
    if plat == "OKX" and not verify_okx_keys(api_key, api_secret, api_passphrase):
        return JSONResponse(status_code=400, content={"success": False, "message": "OKX отклонил ключи! Проверьте Passphrase."})
    if plat in ["Tiger Trade", "Vataga"] and (len(api_key) < 3 or len(api_secret) < 3):
        return JSONResponse(status_code=400, content={"success": False, "message": "Слишком короткие ключи."})
    ex = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id, models.ApiKey.platform == plat).first()
    if ex:
        ex.api_key = api_key; ex.api_secret = api_secret; ex.api_passphrase = api_passphrase or None
    else:
        db.add(models.ApiKey(user_id=user_id, platform=plat, api_key=api_key, api_secret=api_secret, api_passphrase=api_passphrase or None))
    db.commit()
    return {"success": True, "message": f"Ключи {plat} сохранены!"}

@app.post("/api/delete-keys")
async def del_keys(user_id: int = Form(...), platform: str = Form(...), db: Session = Depends(get_db)):
    k = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id, models.ApiKey.platform == platform).first()
    if k: db.delete(k); db.commit()
    return {"success": True}

@app.get("/api/keys/{user_id}")
async def get_keys(user_id: int, db: Session = Depends(get_db)):
    keys = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id).all()
    return {"keys": [{"platform": k.platform, "has_passphrase": bool(k.api_passphrase)} for k in keys]}

# ==================== TRADES ====================
@app.get("/api/trades/{user_id}")
async def get_trades(user_id: int, db: Session = Depends(get_db)):
    trades = db.query(models.Trade).filter(models.Trade.user_id == user_id).order_by(models.Trade.exit_time.desc().nullslast()).all()
    out = []
    for t in trades:
        ed = time.strftime('%d %b %H:%M', time.localtime(t.entry_time)) if t.entry_time else "-"
        xd = time.strftime('%d %b %H:%M', time.localtime(t.exit_time)) if t.exit_time else "-"
        ps = "+" if t.pnl >= 0 else ""
        pps = "+" if t.pnl_percent >= 0 else ""
        out.append({
            "id": t.id,
            "order_id": t.order_id,
            "ticker": t.symbol,
            "exchange": t.platform.lower(),
            "entry": ed,
            "exit": xd,
            "side": "Buy" if t.side.lower() == "buy" else "Sell",
            "pnlPercent": f"{pps}{t.pnl_percent:.2f}%",
            "profit": f"{ps}{t.pnl:.2f} $",
            "revenue": f"{t.qty * t.exit_price:.2f} $",
            "commission": f"{t.commission:.2f} $",
            "volume": f"{t.qty * t.entry_price:.1f} $",
            "entryPrice": t.entry_price,
            "exitPrice": t.exit_price,
            "entryTime": t.entry_time,
            "exitTime": t.exit_time,
            "qty": t.qty
        })
    return {"status": "success", "trades": out}

@app.get("/api/sync-trades/{user_id}")
async def sync_trades(user_id: int, platform: str = Query(None), db: Session = Depends(get_db)):
    keys = db.query(models.ApiKey).filter(models.ApiKey.user_id == user_id).all()
    if not keys:
        return JSONResponse(status_code=400, content={"status": "error", "message": "Сначала добавьте API-ключи!"})
    results = []
    for k in keys:
        if platform and k.platform != platform:
            continue
        if k.platform == "Bybit":
            r = sync_bybit(user_id, k.api_key, k.api_secret, db)
        elif k.platform == "Binance":
            r = sync_binance(user_id, k.api_key, k.api_secret, db)
        elif k.platform == "OKX":
            r = sync_okx(user_id, k.api_key, k.api_secret, k.api_passphrase or "", db)
        elif k.platform == "Tiger Trade":
            r = sync_tiger(user_id, k.api_key, k.api_secret, db)
        elif k.platform == "Vataga":
            r = sync_vataga(user_id, k.api_key, k.api_secret, db)
        else:
            r = {"status": "skip", "message": f"Неизвестная платформа: {k.platform}"}
        results.append({"platform": k.platform, **r})
    trades_data = await get_trades(user_id, db)
    return {"status": "success", "results": results, "trades": trades_data.get("trades", [])}

@app.get("/api/kline")
async def kline(symbol: str, interval: str = "1"):
    url = "https://api.bybit.com/v5/market/kline"
    params = {"category": "linear", "symbol": symbol, "interval": interval, "limit": 200}
    try:
        r = requests.get(url, params=params, timeout=5)
        d = r.json()
        if d.get("retCode") != 0:
            return JSONResponse(status_code=400, content={"error": d.get("retMsg")})
        lst = d.get("result", {}).get("list", [])
        lst.reverse()
        candles = [{"time": int(i[0])//1000, "open": float(i[1]), "high": float(i[2]), "low": float(i[3]), "close": float(i[4]), "volume": float(i[5])} for i in lst]
        return {"candles": candles}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})