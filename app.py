from datetime import datetime, timezone
import hashlib
import secrets
import os

import psycopg
from psycopg.rows import dict_row

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# ============================================================
# CONFIGURAÇÃO
# ============================================================

DATABASE_URL = os.environ["DATABASE_URL"]

app = FastAPI(title="Discord Auto Login - Licensing Server")


# ============================================================
# BANCO DE DADOS
# ============================================================

def get_db():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def init_db():
    with get_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id BIGSERIAL PRIMARY KEY,
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
                id BIGSERIAL PRIMARY KEY,
                license_id BIGINT NOT NULL,
                machine_id_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(license_id, machine_id_hash),
                FOREIGN KEY(license_id)
                    REFERENCES licenses(id)
                    ON DELETE CASCADE
            )
        """)

        conn.commit()


init_db()


# ============================================================
# FUNÇÕES
# ============================================================

def hash_value(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


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

    key_hash = hash_value(
        data.license_key.strip().upper()
    )

    machine_hash = hash_value(
        data.machine_id.strip()
    )

    conn = get_db()

    license_row = conn.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key_hash = %s
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

    # ========================================================
    # VERIFICAR VALIDADE
    # ========================================================

    if license_row["expires_at"]:

        expiration = datetime.fromisoformat(
            license_row["expires_at"]
        )

        if datetime.now(timezone.utc) >= expiration:

            conn.execute(
                """
                UPDATE licenses
                SET status = 'expired'
                WHERE id = %s
                """,
                (license_row["id"],)
            )

            conn.commit()
            conn.close()

            raise HTTPException(
                status_code=403,
                detail="Licença expirada."
            )

    # ========================================================
    # VERIFICAR COMPUTADOR
    # ========================================================

    existing = conn.execute(
        """
        SELECT *
        FROM activations
        WHERE license_id = %s
        AND machine_id_hash = %s
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
            SET last_seen = %s
            WHERE id = %s
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

    # ========================================================
    # CONTAR COMPUTADORES
    # ========================================================

    count_row = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM activations
        WHERE license_id = %s
        """,
        (license_row["id"],)
    ).fetchone()

    count = count_row["count"]

    if count >= license_row["max_machines"]:

        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Limite de computadores atingido."
        )

    # ========================================================
    # NOVA ATIVAÇÃO
    # ========================================================

    now = utc_now()

    conn.execute(
        """
        INSERT INTO activations (
            license_id,
            machine_id_hash,
            first_seen,
            last_seen
        )
        VALUES (%s, %s, %s, %s)
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

    key_hash = hash_value(
        data.license_key.strip().upper()
    )

    machine_hash = hash_value(
        data.machine_id.strip()
    )

    conn = get_db()

    license_row = conn.execute(
        """
        SELECT *
        FROM licenses
        WHERE license_key_hash = %s
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

    # ========================================================
    # VERIFICAR VALIDADE
    # ========================================================

    if license_row["expires_at"]:

        expiration = datetime.fromisoformat(
            license_row["expires_at"]
        )

        if datetime.now(timezone.utc) >= expiration:

            conn.execute(
                """
                UPDATE licenses
                SET status = 'expired'
                WHERE id = %s
                """,
                (license_row["id"],)
            )

            conn.commit()
            conn.close()

            raise HTTPException(
                status_code=403,
                detail="Licença expirada."
            )

    # ========================================================
    # VERIFICAR ATIVAÇÃO
    # ========================================================

    activation = conn.execute(
        """
        SELECT *
        FROM activations
        WHERE license_id = %s
        AND machine_id_hash = %s
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

    # ========================================================
    # ATUALIZAR ÚLTIMO ACESSO
    # ========================================================

    conn.execute(
        """
        UPDATE activations
        SET last_seen = %s
        WHERE id = %s
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
# ============================================================
# ADMINISTRAÇÃO
# ============================================================

from datetime import timedelta


class AdminCreateRequest(BaseModel):
    customer: str
    days: int
    max_machines: int
    admin_key: str


class AdminLicenseRequest(BaseModel):
    license_id: int
    admin_key: str


def check_admin_key(admin_key: str):

    expected = os.environ.get("ADMIN_KEY")

    if not expected:
        raise HTTPException(
            status_code=500,
            detail="ADMIN_KEY não configurada no servidor."
        )

    if not secrets.compare_digest(
        admin_key,
        expected
    ):
        raise HTTPException(
            status_code=403,
            detail="Chave administrativa inválida."
        )


@app.post("/admin/create")
def admin_create(data: AdminCreateRequest):

    check_admin_key(data.admin_key)

    if not data.customer.strip():
        raise HTTPException(
            status_code=400,
            detail="Nome do cliente obrigatório."
        )

    if data.days < 0:
        raise HTTPException(
            status_code=400,
            detail="Quantidade de dias inválida."
        )

    if data.max_machines < 1:
        raise HTTPException(
            status_code=400,
            detail="Quantidade de computadores inválida."
        )

    license_key = generate_license_key()

    if data.days > 0:
        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(days=data.days)
        ).isoformat()
    else:
        expires_at = None

    conn = get_db()

    row = conn.execute(
        """
        INSERT INTO licenses (
            license_key_hash,
            customer,
            status,
            expires_at,
            max_machines,
            created_at
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            hash_value(license_key),
            data.customer.strip(),
            "active",
            expires_at,
            data.max_machines,
            utc_now()
        )
    ).fetchone()

    conn.commit()
    conn.close()

    return {
        "success": True,
        "id": row["id"],
        "customer": data.customer.strip(),
        "license_key": license_key,
        "expires_at": expires_at,
        "max_machines": data.max_machines
    }


@app.post("/admin/list")
def admin_list(data: dict):

    check_admin_key(data.get("admin_key", ""))

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
            id,
            customer,
            status,
            expires_at,
            max_machines,
            created_at
        FROM licenses
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return {
        "licenses": rows
    }


@app.post("/admin/revoke")
def admin_revoke(data: AdminLicenseRequest):

    check_admin_key(data.admin_key)

    conn = get_db()

    result = conn.execute(
        """
        UPDATE licenses
        SET status = 'revoked'
        WHERE id = %s
        """,
        (data.license_id,)
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Licença não encontrada."
        )

    return {
        "success": True,
        "message": "Licença revogada."
    }


@app.post("/admin/activate")
def admin_activate(data: AdminLicenseRequest):

    check_admin_key(data.admin_key)

    conn = get_db()

    result = conn.execute(
        """
        UPDATE licenses
        SET status = 'active'
        WHERE id = %s
        """,
        (data.license_id,)
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Licença não encontrada."
        )

    return {
        "success": True,
        "message": "Licença ativada."
    }
# ============================================================
# EXCLUIR LICENÇA
# ============================================================

@app.post("/admin/delete")
def admin_delete(data: AdminLicenseRequest):

    check_admin_key(data.admin_key)

    conn = get_db()

    conn.execute(
        """
        DELETE FROM activations
        WHERE license_id = %s
        """,
        (data.license_id,)
    )

    result = conn.execute(
        """
        DELETE FROM licenses
        WHERE id = %s
        """,
        (data.license_id,)
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:

        raise HTTPException(
            status_code=404,
            detail="Licença não encontrada."
        )

    return {
        "success": True,
        "message": "Licença excluída permanentemente."
    }
