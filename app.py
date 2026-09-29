from datetime import datetime, timezone
import hashlib
import secrets
import sqlite3

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# ============================================================
# CONFIGURAÇÃO
# ============================================================

DB_FILE = "licenses.db"

app = FastAPI(title="Discord Auto Login - Licensing Server")


# ============================================================
# BANCO DE DADOS
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE NOT NULL,
            customer TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT,
            max_machines INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            machine_id_hash TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(license_id, machine_id_hash),
            FOREIGN KEY(license_id) REFERENCES licenses(id)
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# FUNÇÕES
# ============================================================

def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_license_key() -> str:
    parts = [
        secrets.token_hex(2).upper(),
        secrets.token_hex(2).upper(),
        secrets.token_hex(2).upper(),
        secrets.token_hex(2).upper(),
    ]

    return "ZNC-" + "-".join(parts)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# MODELOS
# ============================================================

class ActivateRequest(BaseModel):
    license_key: str
    machine_id: str


class ValidateRequest(BaseModel):
    license_key: str
    machine_id: str


# ============================================================
# ROTAS
# ============================================================

@app.get("/")
def home():
    return {
        "server": "Discord Auto Login Licensing Server",
        "status": "online"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


# ============================================================
# ATIVAÇÃO
# ============================================================

@app.post("/activate")
def activate(data: ActivateRequest):

    key_hash = hash_value(data.license_key.strip().upper())
    machine_hash = hash_value(data.machine_id.strip())

    conn = get_db()

    license_row = conn.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key_hash = ?
        """,
        (key_hash,)
    ).fetchone()

    if not license_row:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="Licença inválida."
        )

    if license_row["status"] != "active":
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Licença desativada."
        )

    # Verificar validade
    if license_row["expires_at"]:
        expiration = datetime.fromisoformat(
            license_row["expires_at"]
        )

        if datetime.now(timezone.utc) >= expiration:
            conn.execute(
                """
                UPDATE licenses
                SET status = 'expired'
                WHERE id = ?
                """,
                (license_row["id"],)
            )

            conn.commit()
            conn.close()

            raise HTTPException(
                status_code=403,
                detail="Licença expirada."
            )

    # Verificar se este computador já está ativado
    existing = conn.execute(
        """
        SELECT *
        FROM activations
        WHERE license_id = ?
        AND machine_id_hash = ?
        """,
        (
            license_row["id"],
            machine_hash
        )
    ).fetchone()

    if existing:

        conn.execute(
            """
            UPDATE activations
            SET last_seen = ?
            WHERE id = ?
            """,
            (
                utc_now(),
                existing["id"]
            )
        )

        conn.commit()
        conn.close()

        return {
            "success": True,
            "message": "Computador já ativado.",
            "status": "active"
        }

    # Quantidade de computadores já utilizados
    count = conn.execute(
        """
        SELECT COUNT(*)
        FROM activations
        WHERE license_id = ?
        """,
        (license_row["id"],)
    ).fetchone()[0]

    if count >= license_row["max_machines"]:
        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Limite de computadores atingido."
        )

    # Nova ativação
    now = utc_now()

    conn.execute(
        """
        INSERT INTO activations (
            license_id,
            machine_id_hash,
            first_seen,
            last_seen
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            license_row["id"],
            machine_hash,
            now,
            now
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Licença ativada com sucesso.",
        "status": "active"
    }


# ============================================================
# VALIDAÇÃO
# ============================================================

@app.post("/validate")
def validate(data: ValidateRequest):

    key_hash = hash_value(data.license_key.strip().upper())
    machine_hash = hash_value(data.machine_id.strip())

    conn = get_db()

    license_row = conn.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key_hash = ?
        """,
        (key_hash,)
    ).fetchone()

    if not license_row:
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Licença inválida."
        )

    if license_row["status"] != "active":
        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Licença não está ativa."
        )

    if license_row["expires_at"]:

        expiration = datetime.fromisoformat(
            license_row["expires_at"]
        )

        if datetime.now(timezone.utc) >= expiration:

            conn.execute(
                """
                UPDATE licenses
                SET status = 'expired'
                WHERE id = ?
                """,
                (license_row["id"],)
            )

            conn.commit()
            conn.close()

            raise HTTPException(
                status_code=403,
                detail="Licença expirada."
            )

    activation = conn.execute(
        """
        SELECT *
        FROM activations
        WHERE license_id = ?
        AND machine_id_hash = ?
        """,
        (
            license_row["id"],
            machine_hash
        )
    ).fetchone()

    if not activation:
        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Este computador não está ativado."
        )

    conn.execute(
        """
        UPDATE activations
        SET last_seen = ?
        WHERE id = ?
        """,
        (
            utc_now(),
            activation["id"]
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "status": "active"
    }
