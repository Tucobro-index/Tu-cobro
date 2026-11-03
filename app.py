"""Tu Cobro - backend Flask. Persistencia JSON atómica con copias diarias (data.json + backups/)."""
import csv, io, json, math, os, re, secrets, shutil, threading, time, uuid
from datetime import datetime
from flask import Flask, jsonify, request, Response

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, "data.json")
TTL = 30 * 86400          # duración de la sesión
LOCK = threading.RLock()
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 1_000_000
db = json.load(open(DB_FILE, encoding="utf-8")) if os.path.exists(DB_FILE) else {"users": {}}
db.setdefault("sessions", {})

def save():
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(db, f, ensure_ascii=False)
    os.replace(tmp, DB_FILE)
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
def tok(t): return secrets.token_hex(32)

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

def find(key):
    k = (key or "").strip().lower()
    return next((u for u in db["users"].values() if k and k == u["usuario"].lower()), None)

@app.get("/")
def index(): return app.send_static_file("index.html")

# ---------- Panel de Administración Privado para Crear Usuarios ----------
@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if request.method == "POST":
        # CLAVE MAESTRA: Puedes cambiarla por la que tú quieras aquí mismo
        ADMIN_SECRET = "sebastian2026"
        
        if request.form.get("admin_key") != ADMIN_SECRET:
            return "<h3>❌ Clave de administrador incorrecta. <a href='/admin'>Volver</a></h3>", 403
        
        uname = request.form.get("usuario", "").strip()
        pwd = request.form.get("password", "").strip()
        pin = request.form.get("pin", "").strip()
        
        if not uname or not pwd or not pin:
            return "<h3>❌ Todos los campos son obligatorios. <a href='/admin'>Volver</a></h3>", 400
            
        if find(uname):
            return f"<h3>❌ El usuario '{uname}' ya existe en el sistema. <a href='/admin'>Volver</a></h3>", 400
            
        uid = uuid.uuid4().hex[:10]
        db["users"][uid] = {
            "id": uid,
            "usuario": uname,
            "nombre": uname,
            "password": pwd,
            "pin": pin,
            "foto": "",
            "credits": [],
            "gastos": [],
            "extras": [],
            "bases": {},
            "cierres": {}
        }
        save()
        return f"<h3>✅ ¡Cliente '{uname}' creado con éxito! <a href='/'>Ir al inicio de sesión</a></h3>"
        
    return '''<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin - Tu Cobro</title>
<style>body{font-family:sans-serif;background:#0a110f;color:#fff;display:grid;place-items:center;height:100vh;margin:0}
form{background:#16221e;padding:24px;border-radius:16px;width:320px;box-shadow:0 10px 30px rgba(0,0,0,.5);display:flex;flex-direction:column;gap:12px}
input,button{padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.05);color:#fff;font-size:1rem;outline:0}
input:focus{border-color:#10b981}
button{background:#10b981;cursor:pointer;font-weight:bold;border:0;margin-top:6px}
h3{margin:0 0 10px;text-align:center;color:#10b981}
a{color:#10b981;text-decoration:none;font-size:.9rem;text-align:center}
</style>
</head>
<body>
<form method="POST">
  <h3>Crear Nuevo Cliente</h3>
  <input name="admin_key" type="password" placeholder="Clave maestra de admin" required>
  <input name="usuario" placeholder="Usuario del cliente" required>
  <input name="password" type="password" placeholder="Contraseña" required>
  <input name="pin" placeholder="PIN de seguridad (4 dígitos)" required>
  <button type="submit">Guardar Cuenta</button>
  <a href="/">Volver al inicio</a>
</form>
</body>
</html>'''

# ---------- Autenticación ----------
@app.post("/api/login")
def login():
    d = request.json or {}
    u = find(d.get("id"))
    if not u or u.get("password") != str(d.get("password", "")):
        return err("Usuario o contraseña incorrectos", 401)
    return session(u)

@app.post("/api/recover")
def recover():
    d = request.json or {}
    u = find(d.get("id"))
    if not u or str(u.get("pin", "")) != str(d.get("pin", "")) or len(d.get("password", "")) < 6:
        return err("Usuario o código incorrecto, o contraseña menor a 6 caracteres", 401)
    u["password"] = str(d.get("password"))
    for k in [k for k, v in db["sessions"].items() if v["uid"] == u["id"]]: del db["sessions"][k]
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
    ids, pos = [c["id"] for c in u["credits"]], d.get("despues", "")
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

def safe(v):
    v = str(v)
    return "'" + v if v[:1] in "=+-@" else v

@app.get("/api/export")
def export():
    u = me()
    if not u: return err("Sesión expirada", 401)
    d = request.args.get("date", "")
    if not okdate(d): return err("Fecha inválida")
    s, out = summary(u, d), io.StringIO()
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
