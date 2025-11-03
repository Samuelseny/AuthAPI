from fastapi import FastAPI, HTTPException, Header
import sqlite3
import smtplib
from email.mime.text import MIMEText
import secrets
import time
from typing import Optional
from fastapi import Header
import redis
from cryptography.fernet import Fernet


app = FastAPI(title="Microserviço de Autenticação")
redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_ADDRESS = "samuelsantosgg11@gmail.com"
EMAIL_PASSWORD = "hdfz ptjw fblw alwd"

def send_reset_code(email_address):
    code = f"{secrets.randbelow(1000000):06d}"
    key = f"pwdreset:{email_address}"
    redis_client.setex(key, 600, code)
    msg = MIMEText(f"Seu código de recuperação é: {code}")
    msg['Subject'] = "Recuperação de senha"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email_address
    server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
    server.ehlo()
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    server.sendmail(EMAIL_ADDRESS, [email_address], msg.as_string())
    server.quit()
    return True

SECRET_KEY = Fernet.generate_key()
fernet = Fernet(SECRET_KEY)


conn = sqlite3.connect("auth.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    document TEXT UNIQUE,
    password TEXT,
    logged_in INTEGER DEFAULT 0
)
""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_attempts (
    email TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 0,
    last_attempt REAL,
    blocked_until REAL
)
""")
conn.commit()

class User:
    def __init__(self):
        self.conn = conn

    def create_user(self, name, email, document, password):
        try:
            self.conn.execute(
                "INSERT INTO users (name, email, document, password) VALUES (?, ?, ?, ?)",
                (name, email, document, password)
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Email ou documento já cadastrados.")

    def get_by_email(self, email):
        cur = self.conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()

    def get_by_token(self, token):
        try:
            decoded = fernet.decrypt(token.encode()).decode()
            email, document = decoded.split(":")
            cur = self.conn.execute("SELECT * FROM users WHERE email = ? AND document = ?", (email, document))
            return cur.fetchone()
        except Exception:
            return None

    def update_password(self, document, email, new_password):
        cur = self.conn.execute(
            "SELECT * FROM users WHERE document = ? AND email = ?", (document, email)
        )
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")
        self.conn.execute(
            "UPDATE users SET password = ? WHERE document = ? AND email = ?",
            (new_password, document, email)
        )
        self.conn.commit()
        return user

    def set_logged_in(self, email, value):
        self.conn.execute("UPDATE users SET logged_in = ? WHERE email = ?", (value, email))
        self.conn.commit()

    def register_attempt(self, email, success):
        now = time.time()
        cur = self.conn.execute("SELECT attempts, blocked_until FROM login_attempts WHERE email = ?", (email,))
        record = cur.fetchone()

        if success:
            self.conn.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
        else:
            if record:
                attempts, blocked_until = record
                if blocked_until and now < blocked_until:
                    raise HTTPException(status_code=403,
                                        detail="Usuário bloqueado. Aguarde 10 minutos para tentar novamente.")
                attempts += 1
                if attempts >= 3:
                    blocked_until = now + 600
                    attempts = 0
                self.conn.execute("""
                    UPDATE login_attempts
                    SET attempts = ?, blocked_until = ?
                    WHERE email = ?
                """, (attempts, blocked_until, email))
            else:
                self.conn.execute("""
                    INSERT INTO login_attempts (email, attempts, blocked_until)
                    VALUES (?, ?, NULL)
                """, (email, 1))
        self.conn.commit()


class AuthService:
    def __init__(self, user_model: User):
        self.user_model = user_model

    def generate_token(self, email, document):
        data = f"{email}:{document}"
        token = fernet.encrypt(data.encode()).decode()
        return token

    def signup(self, name, email, document, password):
        self.user_model.create_user(name, email, document, password)
        token = self.generate_token(email, document)
        return {"token": token}

    def login(self, email, password):
        user = self.user_model.get_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")

        try:
            self.user_model.register_attempt(email, success=False)
        except HTTPException as e:
            raise e

        if user[4] != password:
            raise HTTPException(status_code=401, detail="Senha incorreta.")

        self.user_model.register_attempt(email, success=True)
        self.user_model.set_logged_in(email, 1)

        token = self.generate_token(email, user[3])
        return {"token": token}

    def recuperar_senha(self, document, email, new_password):
        user = self.user_model.update_password(document, email, new_password)
        token = self.generate_token(user[2], user[3])
        return {"token": token}

    def logout(self, token):
        user = self.user_model.get_by_token(token)
        if not user:
            raise HTTPException(status_code=400, detail="Token inválido.")
        self.user_model.set_logged_in(user[2], 0)
        return {"message": "Logout realizado com sucesso."}

    def me(self, token):
        user = self.user_model.get_by_token(token)
        if not user:
            raise HTTPException(status_code=400, detail="Token inválido.")
        return {
            "id": user[0],
            "name": user[1],
            "email": user[2],
            "document": user[3],
            "password": user[4],
            "logged_in": bool(user[5])
        }


user_model = User()
auth_service = AuthService(user_model)

@app.post("/api/v1/auth/signup")
def signup(data: dict):
    limit = 10
    window = 60
    key = f"ratelimit:<signup>:{time.time() // window}"

    requests = redis_client.incr(key)
    if requests == 1:
        redis_client.expire(key, window)
    if requests > limit:
        raise HTTPException(status_code=429, detail="Limite de requisições atingido. Tente novamente mais tarde.")


    return auth_service.signup(
        data.get("name"), data.get("email"), data.get("document"), data.get("password")
    )


@app.post("/api/v1/auth/login")
def login(data: dict):
    limit = 10
    window = 60
    key = f"ratelimit:<login>:{time.time() // window}"

    requests = redis_client.incr(key)
    if requests == 1:
        redis_client.expire(key, window)
    if requests > limit:
        raise HTTPException(status_code=429, detail="Limite de requisições atingido. Tente novamente mais tarde.")

    return auth_service.login(data.get("login"), data.get("password"))


@app.post("/api/v1/auth/reset-password")
def reset_password(data: dict):
    return auth_service.recuperar_senha(
        data.get("document"), data.get("email"), data.get("new_password")
    )

@app.post("/api/v1/auth/request-password-reset")
def request_password_reset(data: dict):
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email ausente.")
    user = user_model.get_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    send_reset_code(email)
    return {"mensagem": "Código de verificação enviado para o e-mail cadastrado."}

@app.post("/api/v1/auth/confirm-password-reset")
def confirm_password_reset(data: dict):
    email = data.get("email")
    codigo = data.get("codigo")
    nova_senha = data.get("new_password")
    if not email or not codigo or not nova_senha:
        raise HTTPException(status_code=400, detail="Dados ausentes.")
    key = f"pwdreset:{email}"
    codigo_salvo = redis_client.get(key)
    if not codigo_salvo:
        raise HTTPException(status_code=400, detail="Código expirado ou inválido.")
    if codigo_salvo != codigo:
        raise HTTPException(status_code=400, detail="Código incorreto.")
    user_model.update_password(user_model.get_by_email(email)[3], email, nova_senha)
    redis_client.delete(key)
    return {"mensagem": "Senha redefinida com sucesso."}

@app.post("/api/v1/auth/logout")
def logout(data: dict):
    limit = 10
    window = 60
    key = f"ratelimit:<logout>:{time.time() // window}"

    requests = redis_client.incr(key)
    if requests == 1:
        redis_client.expire(key, window)
    if requests > limit:
        raise HTTPException(status_code=429, detail="Limite de requisições atingido. Tente novamente mais tarde.")
    token = data.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente.")

    return auth_service.logout(token)

@app.get("/api/v1/auth/me")
def me(Authorization: Optional[str] = Header(None, description="Token no formato: SDWork <token>")):
    if not Authorization or not Authorization.startswith("SDWork "):
        raise HTTPException(status_code=400, detail="Cabeçalho Authorization inválido.")
    token = Authorization.replace("SDWork ", "")

    limit = 5
    window = 30
    key = f"throttle:me:{token}"

    requests = redis_client.incr(key)
    if requests == 1:
        redis_client.expire(key, window)
    if requests > limit:
        raise HTTPException(status_code=429, detail="Muitas requisições. Tente novamente mais tarde.")

    return auth_service.me(token)