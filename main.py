from fastapi import FastAPI, HTTPException, Header
import sqlite3
import base64
import time

app = FastAPI(title="Microserviço de Autenticação")

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
            decoded = base64.b64decode(token).decode()
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
        return base64.b64encode(data.encode()).decode()

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
    return auth_service.signup(
        data.get("name"), data.get("email"), data.get("document"), data.get("password")
    )


@app.post("/api/v1/auth/login")
def login(data: dict):
    return auth_service.login(data.get("login"), data.get("password"))


@app.post("/api/v1/auth/recuperar-senha")
def recuperar_senha(data: dict):
    return auth_service.recuperar_senha(
        data.get("document"), data.get("email"), data.get("new_password")
    )


@app.post("/api/v1/auth/logout")
def logout(data: dict):
    token = data.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente.")
    return auth_service.logout(token)

@app.post("/api/v1/auth/me")
def me(data: dict):
    token = data.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente.")
    return auth_service.me(token)
