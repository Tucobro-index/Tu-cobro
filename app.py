"""Tu Cobro - backend Flask. Persistencia JSON atómica con copias diarias (data.json + backups/)."""
import csv, hashlib, io, json, math, os, re, secrets, shutil, threading, time, uuid
from datetime import datetime
from flask import Flask, jsonify, request, Response
from werkzeug.security import check_password_hash as chk, generate_password_hash as gen

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, "data.json")
TTL = 30 * 86400          # duración de la sesión
LOCK = threading.RLock()
FAILS = {}                # intentos fallidos: clave -> (n, último)
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 1_000_000
db = json.load(open(DB_FILE, encoding="utf-8")) if os.path.exists(DB_FILE) else {"users": {}}
db.setdefault("sessions", {})

def save():
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(db, f, ensure_ascii=False)
    os.replace(tmp, DB_FILE)                     # escritura atómica: nunca queda a medias
    bd = os.path.join(BASE, "backups"); os.makedirs(bd, exist_ok=True)
    shutil.copy(DB_FILE, os.path.join(bd, f"data-{datetime.now():%Y%m%d}.json"))
    for old in sorted(os.listdir(bd))[:-14]: os.remove(os.path.join(bd, old))

@app.before_request
def _lock(): LOCK.acquire()
@app.teardown_request
def _unlock(e): LOCK.release()
@app.after_request
def headers(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                      "Referrer-Policy": "same-origin", "Cache-Control": "no-store" if request.path.startswith("/api") else "no-cache"})
    return r

def err(msg, code=400): return jsonify(error=msg), code
def okdate(s): return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", s or ""))
def digits(s): return "".join(c for c in str(s) if c.isdigit())
def public(u): return {k: u[k] for k in ("id", "usuario", "email", "tel", "nombre", "foto")}
def tok(t): return hashlib.sha256(t.encode()).hexdigest()

def session(u):
    t = secrets.token_urlsafe(32)
    now = time.time()
    db["sessions"] = {k: v for k, v in db["sessions"].items() if v["exp"] > now}
    db["sessions"][tok(t)] = {"uid": u["id"], "exp": now + TTL}
    save()
    return jsonify(token=t, user=public(u))

def me():
    s = db["sessions"].get(tok(request.headers.get("X-Token", "")))
    u = db["users"].get(s["uid"]) if s and s["exp"] > time.time() else None
    if u:
        for k, v in (("extras", []), ("cierres", {}), ("gastos", []), ("bases", {})): u.setdefault(k, v)
    return u

def throttled(key):
    n, t = FAILS.get(key, (0, 0))
    return n >= 5 and time.time() - t < 600
def failed(key): FAILS[key] = (FAILS.get(key, (0, 0))[0] + 1, time.time())

def find(key):
    k = (key or "").strip().lower()
    return next((u for u in db["users"].values() if k and k in (u["usuario"].lower(), u["email"].lower(), u["tel"])), None)

def new_user(usuario, email, tel, password, pin, nombre=""):
    u = dict(id=uuid.uuid4().hex, usuario=usuario, email=email, tel=tel, nombre=nombre, foto="", hash=gen(password), pin=gen(pin),
             credits=[], gastos=[], extras=[], bases={}, cierres={})
    db["users"][u["id"]] = u
    save()
    return u

@app.get("/")
def index(): return app.send_static_file("index.html")

# ---------- Autenticación ----------
@app.post("/api/login")
def login():
    d = request.json or {}
    key = f"{request.remote_addr}:{str(d.get('id', '')).lower()}"
    if throttled(key): return err("Demasiados intentos. Espera 10 minutos e inténtalo de nuevo", 429)
    u = find(d.get("id"))
    if not u or not chk(u["hash"], d.get("password", "")):
        failed(key); return err("Datos de acceso incorrectos", 401)
    FAILS.pop(key, None)
    return session(u)

@app.post("/api/recover")
def recover():
    d = request.json or {}
    key = f"rec:{request.remote_addr}:{str(d.get('id', '')).lower()}"
    if throttled(key): return err("Demasiados intentos. Espera 10 minutos", 429)
    u = find(d.get("id"))
    if not u or not chk(u["pin"], str(d.get("pin", ""))) or len(d.get("password", "")) < 6:
        failed(key); return err("Usuario o código incorrecto, o contraseña menor a 6 caracteres", 401)
    FAILS.pop(key, None)
    u["hash"] = gen(d["password"])
    for k in [k for k, v in db["sessions"].items() if v["uid"] == u["id"]]: del db["sessions"][k]  # cierra otras sesiones
    save()
    return jsonify(ok=True)

@app.post("/api/logout")
def logout():
    db["sessions"].pop(tok(request.headers.get("X-Token", "")), None); save()
    return jsonify(ok=True)

@app.get("/api/me")
def whoami():
    u = me()
    return (jsonify(user=public(u)) if u else err("Sesión expirada", 401))

@app.put("/api/profile")
def profile():
    u = me()
    if not u: return err("Sesión expirada", 401)
    d = request.json or {}
    if "nombre" in d: u["nombre"] = str(d["nombre"]).strip()[:40]
    if "foto" in d and str(d["foto"]).startswith("data:image/") and len(d["foto"]) < 400_000: u["foto"] = d["foto"]
    save()
    return jsonify(user=public(u))

# ---------- Cobros ----------
def closed(u, f): return bool(u["cierres"].get(f))

def summary(u, d):
    rows, activos, hist, rec, cartera = [], [], [], 0, 0
    for c in u["credits"]:
        pagado = sum(a["monto"] for a in c["abonos"])
        saldo, bal = max(round(c["total"] - pagado), 0), c["total"]
        hoy = sum(a["monto"] for a in c["abonos"] if a["fecha"] == d)
        rec += hoy; cartera += saldo
        for a in c["abonos"]:
            bal -= a["monto"]
            hist.append(dict(fecha=a["fecha"], cliente=c["cliente"], monto=a["monto"], saldo=max(round(bal), 0)))
        if saldo > 0: activos.append(dict(cliente=c["cliente"], total=c["total"], saldo=saldo))
        if saldo > 0 or hoy > 0:
            est = "Pagado" if hoy >= c["cuota"] or saldo <= 0 else ("En espera" if c.get("espera") == d else "Pendiente")
            rows.append({**{k: c.get(k, "") for k in ("id", "cliente", "cc", "direccion", "tel", "total", "cuota")}, "saldo": saldo, "hoy": hoy, "estado": est,
                         "faltan": math.ceil(saldo / c["cuota"]) if saldo else 0})
    egresos = sum(c["capital"] for c in u["credits"] if c["fecha"] == d)
    gastos, extras = [g for g in u["gastos"] if g["fecha"] == d], [x for x in u["extras"] if x["fecha"] == d]
    gt, et, base = sum(g["monto"] for g in gastos), sum(x["monto"] for x in extras), u["bases"].get(d, 0)
    hist.sort(key=lambda h: h["fecha"], reverse=True)
    return dict(rows=rows, activos=activos, historial=hist[:80], recaudo=rec, cartera=cartera, base=base, egresos=egresos,
                gastos=gastos, gastos_total=gt, extras=extras, extras_total=et, abierta=not closed(u, d),
                caja=base + rec + et - egresos - gt)

def guard(f):
    u = me()
    if not u: return None, err("Sesión expirada", 401)
    if not okdate(f): return None, err("Fecha inválida")
    if closed(u, f): return None, err("La caja de ese día está cerrada. Ábrela para registrar movimientos", 423)
    return u, None

@app.get("/api/data")
def data():
    u = me()
    if not u: return err("Sesión expirada", 401)
    if not okdate(request.args.get("date")): return err("Fecha inválida")
    return jsonify(summary(u, request.args["date"]))

@app.post("/api/credits")
def new_credit():
    d = request.json or {}
    u, e = guard(d.get("fecha"))
    if e: return e
    try:
        cap, it, dias = float(d["capital"]), float(d["interes"]), int(d["dias"])
        assert 0 < cap < 1e10 and 0 <= it <= 1000 and 0 < dias <= 1000 and str(d.get("cliente", "")).strip()
    except Exception: return err("Revisa cliente, capital, interés y plazo")
    total = cap * (1 + it / 100)
    nc = dict(id=uuid.uuid4().hex[:8], cliente=d["cliente"].strip()[:80], cc=digits(d.get("cc", ""))[:15],
                             direccion=str(d.get("direccion", "")).strip()[:120], tel=digits(d.get("tel", ""))[:15], capital=cap,
                             interes=it, dias=dias, total=round(total), cuota=math.ceil(total / dias), fecha=d["fecha"], abonos=[])
    ids, pos = [c["id"] for c in u["credits"]], d.get("despues", "")  # posición en la ruta
    u["credits"].insert(ids.index(pos) + 1 if pos in ids else (0 if not pos else len(ids)), nc)
    save()
    return jsonify(ok=True)

@app.post("/api/credits/<cid>/pay")
def pay(cid):
    d = request.json or {}
    u, e = guard(d.get("fecha"))
    if e: return e
    c = next((c for c in u["credits"] if c["id"] == cid), None)
    try: m = float(d["monto"]); assert 0 < m < 1e10 and c
    except Exception: return err("Monto inválido")
    c["abonos"].append(dict(fecha=d["fecha"], monto=m)); c.pop("espera", None)
    save()
    return jsonify(ok=True)

@app.post("/api/credits/<cid>/wait")
def wait(cid):
    d = request.json or {}
    u, e = guard(d.get("fecha"))
    if e: return e
    c = next((c for c in u["credits"] if c["id"] == cid), None)
    if c: c["espera"] = d["fecha"]; save()
    return jsonify(ok=True)

@app.post("/api/cash")
def cash():
    d = request.json or {}
    if d.get("tipo") == "cierre":
        u = me()
        if not u: return err("Sesión expirada", 401)
        if not okdate(d.get("fecha")): return err("Fecha inválida")
        (u["cierres"].pop(d["fecha"], None) if d.get("abierta") else u["cierres"].__setitem__(d["fecha"], True))
        save(); return jsonify(ok=True)
    u, e = guard(d.get("fecha"))
    if e: return e
    try: m = float(d["monto"]); assert 0 <= m < 1e10
    except Exception: return err("Monto inválido")
    t, concepto = d.get("tipo"), (str(d.get("concepto", "")).strip() or "Sin concepto")[:60]
    if t == "base": u["bases"][d["fecha"]] = m
    elif t == "gasto": u["gastos"].append(dict(fecha=d["fecha"], concepto=concepto, monto=m))
    elif t == "extra": u["extras"].append(dict(fecha=d["fecha"], concepto=concepto, monto=m))
    else: return err("Operación inválida")
    save()
    return jsonify(ok=True)

def safe(v):  # evita inyección de fórmulas al abrir el CSV en Excel
    v = str(v)
    return "'" + v if v[:1] in "=+-@" else v

@app.get("/api/export")
def export():
    u = me()
    if not u: return err("Sesión expirada", 401)
    d = request.args.get("date", "")
    if not okdate(d): return err("Fecha inválida")
    s, out = summary(u, d), io.StringIO()
    # Usamos punto y coma (;) como delimitador para que Excel separe las columnas correctamente
    w = csv.writer(out, delimiter=';')
    w.writerow(["Tu Cobro", d]); w.writerow([])
    w.writerow(["Cliente", "Cuota diaria", "Cuotas pendientes", "Abonó hoy", "Saldo", "Estado"])
    for r in s["rows"]: w.writerow([safe(r["cliente"]), r["cuota"], r["faltan"], r["hoy"], r["saldo"], r["estado"]])
    w.writerow([])
    for k, v in [("Base inicial", s["base"]), ("Ingresos (recaudo)", s["recaudo"]), ("Entradas adicionales", s["extras_total"]),
                 ("Créditos entregados", s["egresos"]), ("Gastos", s["gastos_total"]), ("Efectivo en caja", s["caja"]), ("Cartera activa", s["cartera"])]:
        w.writerow([k, v])
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=tu-cobro-{d}.csv"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("TUCOBRO_DEBUG") == "1")
