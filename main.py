import os, shutil, hmac, hashlib, time, requests, bcrypt, base64
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

def hash_password(p): 
    return bcrypt.hashpw(p.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def hmac_sign(s, p): 
    return hmac.new(s.encode(), p.encode(), hashlib.sha256).hexdigest()

# ==================== BYBIT ====================
def verify_bybit(k, s):
    try:
        ts = str(int(time.time()*1000))
        qs = "accountType=UNIFIED"
        sig = hmac_sign(s, ts+k+"5000"+qs)
        h = {"X-BAPI-API-KEY":k,"X-BAPI-SIGN":sig,"X-BAPI-TIMESTAMP":ts,"X-BAPI-RECV-WINDOW":"5000"}
        r = requests.get(f"https://api.bybit.com/v5/account/wallet-balance?{qs}", headers=h, timeout=8)
        return r.json().get("retCode")==0, None
    except Exception as e:
        return False, str(e)

def bybit_req(k, s, ep, qs=""):
    ts = str(int(time.time()*1000))
    sig = hmac_sign(s, ts+k+"5000"+qs)
    h = {"X-BAPI-API-KEY":k,"X-BAPI-SIGN":sig,"X-BAPI-TIMESTAMP":ts,"X-BAPI-RECV-WINDOW":"5000"}
    url = f"https://api.bybit.com{ep}" + (f"?{qs}" if qs else "")
    return requests.get(url, headers=h, timeout=10).json()

def sync_bybit(uid, k, s, db):
    d = bybit_req(k, s, "/v5/position/closed-pnl", "category=linear&limit=50")
    if d.get("retCode")!=0: 
        return {"status":"error","message":f"Bybit: {d.get('retMsg')}"}
    cnt=0
    for it in d.get("result",{}).get("list",[]):
        oid=it.get("orderId")
        if not oid: continue
        ex=db.query(models.Trade).filter(models.Trade.user_id==uid, models.Trade.order_id==oid).first()
        ent=float(it.get('avgEntryPrice',0)); exi=float(it.get('avgExitPrice',0))
        pnl=float(it.get('closedPnl',0)); cev=float(it.get('cumEntryValue',0))
        of=float(it.get('openFee',0)); cf=float(it.get('closeFee',0))
        pp=(pnl/cev*100) if cev>0 else 0
        ets=int(it.get('createdTime',0))//1000; xts=int(it.get('updatedTime',0))//1000
        if ex:
            ex.exit_price=exi; ex.pnl=pnl; ex.pnl_percent=pp; ex.close_fee=cf; ex.commission=of+cf; ex.exit_time=xts
        else:
            db.add(models.Trade(user_id=uid, order_id=oid, platform="Bybit", symbol=it.get('symbol',''), side=it.get('side','Buy'),
                entry_price=ent, exit_price=exi, qty=float(it.get('qty',0)), pnl=pnl, pnl_percent=pp,
                open_fee=of, close_fee=cf, commission=of+cf, entry_time=ets, exit_time=xts)); cnt+=1
    db.commit(); 
    return {"status":"success","count":cnt}

# ==================== BINANCE ====================
def verify_binance(k, s):
    try:
        ts = str(int(time.time()*1000))
        qs = f"timestamp={ts}"
        sig = hmac_sign(s, qs)
        h = {"X-MBX-APIKEY": k}
        # Проверяем фьючерсы
        r = requests.get(f"https://fapi.binance.com/fapi/v2/account?{qs}&signature={sig}", headers=h, timeout=8)
        if r.status_code == 200: 
            return True, None
        # Если не фьючерсы — пробуем спот
        r2 = requests.get(f"https://api.binance.com/api/v3/account?{qs}&signature={sig}", headers=h, timeout=8)
        if r2.status_code == 200: 
            return True, None
        return False, f"Binance ответил: {r.status_code} — {r.text[:300]}"
    except Exception as e:
        return False, str(e)

def sync_binance(uid, k, s, db):
    try:
        ts = str(int(time.time()*1000))
        qs = f"incomeType=REALIZED_PNL&limit=50&timestamp={ts}"
        sig = hmac_sign(s, qs)
        h = {"X-MBX-APIKEY": k}
        r = requests.get(f"https://fapi.binance.com/fapi/v1/income?{qs}&signature={sig}", headers=h, timeout=10)
        data = r.json()
        if r.status_code != 200: 
            return {"status":"error","message":f"Binance: {data}"}
        cnt=0
        for it in data:
            tid=f"BNB_{it.get('tranId')}"
            if db.query(models.Trade).filter(models.Trade.user_id==uid, models.Trade.order_id==tid).first(): 
                continue
            tms=int(it.get('time',0))//1000; inc=float(it.get('income',0)); sym=it.get('symbol','')
            if not sym: continue
            db.add(models.Trade(user_id=uid, order_id=tid, platform="Binance", symbol=sym,
                side="Buy" if inc>=0 else "Sell", entry_price=0, exit_price=0, qty=0,
                pnl=inc, pnl_percent=0, commission=0, entry_time=tms, exit_time=tms)); cnt+=1
        db.commit(); 
        return {"status":"success","count":cnt}
    except Exception as e:
        return {"status":"error","message":f"Binance sync error: {str(e)}"}

# ==================== OKX ====================
def verify_okx(k, s, ph):
    try:
        ts = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        msg = ts + "GET" + "/api/v5/account/balance"
        sig = base64.b64encode(hmac.new(s.encode(), msg.encode(), hashlib.sha256).digest()).decode()
        h = {"OK-ACCESS-KEY":k,"OK-ACCESS-SIGN":sig,"OK-ACCESS-TIMESTAMP":ts,"OK-ACCESS-PASSPHRASE":ph}
        r = requests.get("https://www.okx.com/api/v5/account/balance", headers=h, timeout=8)
        return r.json().get("code")=="0", None
    except Exception as e:
        return False, str(e)

def sync_okx(uid, k, s, ph, db):
    try:
        ts = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
        path = "/api/v5/account/positions-history?instType=SWAP"
        sig = base64.b64encode(hmac.new(s.encode(), (ts+"GET"+path).encode(), hashlib.sha256).digest()).decode()
        h = {"OK-ACCESS-KEY":k,"OK-ACCESS-SIGN":sig,"OK-ACCESS-TIMESTAMP":ts,"OK-ACCESS-PASSPHRASE":ph}
        r = requests.get(f"https://www.okx.com{path}", headers=h, timeout=10)
        d = r.json()
        if d.get("code")!="0": 
            return {"status":"error","message":f"OKX: {d.get('msg')}"}
        cnt=0
        for it in d.get("data",[]):
            pid=it.get("posId")
            if not pid: continue
            ex=db.query(models.Trade).filter(models.Trade.user_id==uid, models.Trade.order_id==pid).first()
            pnl=float(it.get('pnl',0)); pnr=float(it.get('pnlRatio',0))*100
            otm=int(it.get('openTime',''))//1000 if it.get('openTime') else None
            ctm=int(it.get('closeTime',''))//1000 if it.get('closeTime') else None
            if ex:
                ex.exit_price=float(it.get('avgClosePx',0)); ex.pnl=pnl; ex.pnl_percent=pnr; ex.exit_time=ctm
            else:
                db.add(models.Trade(user_id=uid, order_id=pid, platform="OKX", symbol=it.get('instId',''),
                    side="Buy" if it.get('posSide')=='long' else "Sell",
                    entry_price=float(it.get('avgOpenPx',0)), exit_price=float(it.get('avgClosePx',0)),
                    qty=float(it.get('openMaxPos',0)), pnl=pnl, pnl_percent=pnr,
                    entry_time=otm, exit_time=ctm)); cnt+=1
        db.commit(); 
        return {"status":"success","count":cnt}
    except Exception as e:
        return {"status":"error","message":f"OKX sync error: {str(e)}"}

def sync_tiger(uid, k, s, db):
    return {"status":"info","message":"Tiger Trade: ручное добавление (API недоступен)"}
def sync_vataga(uid, k, s, db):
    return {"status":"info","message":"Vataga: ручное добавление (API недоступен)"}

# ==================== PAGES ====================
@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.get("/dashboard/{user_id}", response_class=HTMLResponse)
def dashboard(request: Request, user_id: int, db: Session = Depends(get_db)):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u: 
        return templates.TemplateResponse(request=request, name="register.html", context={"error":"Пользователь не найден"})
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": u})

@app.post("/register", response_class=HTMLResponse)
async def register(request: Request, name: str = Form(""), username: str = Form(""), password: str = Form(""),
                   avatar: UploadFile = File(None), db: Session = Depends(get_db)):
    if not name.strip() or not username.strip() or not password.strip():
        return templates.TemplateResponse(request=request, name="register.html", context={"error":"Заполните все поля!","name":name,"username":username})
    if db.query(models.User).filter(models.User.username == username).first():
        return templates.TemplateResponse(request=request, name="register.html", context={"error":"Логин занят.","name":name,"username":username})
    av=None
    if avatar and avatar.filename:
        path=f"static/uploads/{username}_{avatar.filename}"
        with open(path,"wb") as f: shutil.copyfileobj(avatar.file, f)
        av=f"/{path}"
    u=models.User(name=name, username=username, hashed_password=hash_password(password), avatar_url=av)
    db.add(u); db.commit(); db.refresh(u)
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"user": u})

# ==================== API KEYS ====================
@app.post("/api/save-keys")
async def save_keys(user_id: int = Form(...), platform: str = Form(...), api_key: str = Form(...),
                    api_secret: str = Form(...), api_passphrase: str = Form(""), db: Session = Depends(get_db)):
    plat = platform.strip()
    ok, err = False, None
    if plat == "Bybit": ok, err = verify_bybit(api_key, api_secret)
    elif plat == "Binance": ok, err = verify_binance(api_key, api_secret)
    elif plat == "OKX": ok, err = verify_okx(api_key, api_secret, api_passphrase)
    elif plat in ["Tiger Trade","Vataga"]: ok, err = (len(api_key)>=3 and len(api_secret)>=3), None
    else: 
        return JSONResponse(status_code=400, content={"success":False,"message":"Неизвестная платформа"})
    
    if not ok:
        msg = f"{plat} отклонил ключи!" + (f" ({err})" if err else "")
        return JSONResponse(status_code=400, content={"success":False,"message":msg})
    
    ex = db.query(models.ApiKey).filter(models.ApiKey.user_id==user_id, models.ApiKey.platform==plat).first()
    if ex:
        ex.api_key=api_key; ex.api_secret=api_secret; ex.api_passphrase=api_passphrase or None
    else:
        db.add(models.ApiKey(user_id=user_id, platform=plat, api_key=api_key, api_secret=api_secret, api_passphrase=api_passphrase or None))
    db.commit()
    return {"success":True,"message":f"Ключи {plat} сохранены!"}

@app.post("/api/delete-keys")
async def del_keys(user_id: int = Form(...), platform: str = Form(...), db: Session = Depends(get_db)):
    k = db.query(models.ApiKey).filter(models.ApiKey.user_id==user_id, models.ApiKey.platform==platform).first()
    if k: db.delete(k); db.commit()
    return {"success":True}

@app.get("/api/keys/{user_id}")
async def get_keys(user_id: int, db: Session = Depends(get_db)):
    keys = db.query(models.ApiKey).filter(models.ApiKey.user_id==user_id).all()
    return {"keys":[{"platform":k.platform,"has_passphrase":bool(k.api_passphrase)} for k in keys]}

# ==================== TRADES ====================
@app.get("/api/trades/{user_id}")
async def get_trades(user_id: int, db: Session = Depends(get_db)):
    trades = db.query(models.Trade).filter(models.Trade.user_id==user_id).order_by(models.Trade.exit_time.desc().nullslast()).all()
    out=[]
    for t in trades:
        ed=time.strftime('%d %b %H:%M',time.localtime(t.entry_time)) if t.entry_time else "-"
        xd=time.strftime('%d %b %H:%M',time.localtime(t.exit_time)) if t.exit_time else "-"
        ps="+" if t.pnl>=0 else ""; pps="+" if t.pnl_percent>=0 else ""
        out.append({
            "id":t.id,"order_id":t.order_id,"ticker":t.symbol,"exchange":t.platform.lower(),
            "entry":ed,"exit":xd,"side":"Buy" if t.side.lower()=="buy" else "Sell",
            "pnlPercent":f"{pps}{t.pnl_percent:.2f}%","profit":f"{ps}{t.pnl:.2f} $",
            "revenue":f"{t.qty*t.exit_price:.2f} $","commission":f"{t.commission:.2f} $","volume":f"{t.qty*t.entry_price:.1f} $",
            "entryPrice":t.entry_price,"exitPrice":t.exit_price,"entryTime":t.entry_time,"exitTime":t.exit_time,"qty":t.qty
        })
    return {"status":"success","trades":out}

@app.get("/api/sync-trades/{user_id}")
async def sync_trades(user_id: int, platform: str = Query(None), db: Session = Depends(get_db)):
    keys = db.query(models.ApiKey).filter(models.ApiKey.user_id==user_id).all()
    if not keys:
        return JSONResponse(status_code=400, content={"status":"error","message":"Сначала добавьте API-ключи!"})
    results=[]
    for k in keys:
        if platform and k.platform!=platform: continue
        if k.platform=="Bybit": r=sync_bybit(user_id,k.api_key,k.api_secret,db)
        elif k.platform=="Binance": r=sync_binance(user_id,k.api_key,k.api_secret,db)
        elif k.platform=="OKX": r=sync_okx(user_id,k.api_key,k.api_secret,k.api_passphrase or "",db)
        elif k.platform=="Tiger Trade": r=sync_tiger(user_id,k.api_key,k.api_secret,db)
        elif k.platform=="Vataga": r=sync_vataga(user_id,k.api_key,k.api_secret,db)
        else: r={"status":"skip","message":f"Неизвестная платформа: {k.platform}"}
        results.append({"platform":k.platform,**r})
    td = await get_trades(user_id, db)
    return {"status":"success","results":results,"trades":td.get("trades",[])}

@app.get("/api/kline")
async def kline(symbol: str, interval: str = "1"):
    url="https://api.bybit.com/v5/market/kline"
    params={"category":"linear","symbol":symbol,"interval":interval,"limit":200}
    try:
        r=requests.get(url,params=params,timeout=5)
        d=r.json()
        if d.get("retCode")!=0: 
            return JSONResponse(status_code=400, content={"error":d.get("retMsg")})
        lst=d.get("result",{}).get("list",[]); lst.reverse()
        candles=[{"time":int(i[0])//1000,"open":float(i[1]),"high":float(i[2]),"low":float(i[3]),"close":float(i[4]),"volume":float(i[5])} for i in lst]
        return {"candles":candles}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error":str(e)})