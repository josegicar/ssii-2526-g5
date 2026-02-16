import hmac
import hashlib
import uuid
import time
import os
import json

from config import (
    MASTER_KEY, NONCE_WINDOW_SECONDS, PBKDF2_ITERATIONS,
    NONCES_FILE, SEPARATOR, FIELD_SEPARATOR
)


# ============================================================
# HKDF - Derivacion de claves de sesion (contra key derivation)
# ============================================================

def hkdf_derive_key(master_key: bytes, salt: bytes, info: bytes = b"session_key", length: int = 32) -> bytes:
    """Deriva una clave de sesion usando HKDF (extract-then-expand)."""
    # Extract
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    # Expand
    t = b""
    okm = b""
    for i in range(1, (length // 32) + 2):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def generate_session_key(session_salt: bytes = None) -> tuple:
    """Genera una clave de sesion derivada de la master key."""
    if session_salt is None:
        session_salt = os.urandom(16)
    session_key = hkdf_derive_key(MASTER_KEY, session_salt)
    return session_key, session_salt


# ============================================================
# MAC - HMAC-SHA256 (contra MiTM)
# ============================================================

def generate_mac(message: str, nonce: str, seq: int, key: bytes) -> str:
    """Genera HMAC-SHA256 del mensaje + nonce + seq."""
    data = f"{message}{nonce}{seq}".encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_mac(message: str, nonce: str, seq: int, received_mac: str, key: bytes) -> bool:
    """Verifica MAC con comparacion en tiempo constante (contra timing attacks)."""
    expected_mac = generate_mac(message, nonce, seq, key)
    return hmac.compare_digest(expected_mac, received_mac)


# ============================================================
# NONCE con timestamp (contra Replay)
# ============================================================

def generate_nonce() -> str:
    """Genera nonce unico: UUID4 + timestamp."""
    return f"{uuid.uuid4().hex}-{int(time.time())}"


def parse_nonce_timestamp(nonce: str) -> int:
    """Extrae el timestamp de un nonce."""
    try:
        return int(nonce.split("-")[-1])
    except (ValueError, IndexError):
        return 0


def load_used_nonces() -> dict:
    """Carga nonces usados desde fichero."""
    if os.path.exists(NONCES_FILE):
        with open(NONCES_FILE, "r") as f:
            return json.load(f)
    return {}


def save_used_nonces(nonces: dict):
    """Guarda nonces usados en fichero."""
    with open(NONCES_FILE, "w") as f:
        json.dump(nonces, f)


def is_nonce_valid(nonce: str, used_nonces: dict) -> tuple:
    """
    Valida un nonce. Retorna (valido, razon_error).
    - No debe estar repetido
    - Timestamp debe estar dentro de la ventana
    """
    # Verificar timestamp dentro de ventana
    nonce_time = parse_nonce_timestamp(nonce)
    current_time = int(time.time())

    if abs(current_time - nonce_time) > NONCE_WINDOW_SECONDS:
        return False, "Nonce fuera de ventana temporal"

    # Verificar no repetido
    if nonce in used_nonces:
        return False, "Nonce ya utilizado (posible replay)"

    return True, "OK"


def cleanup_old_nonces(used_nonces: dict) -> dict:
    """Elimina nonces con mas de 10 minutos de antiguedad."""
    current_time = int(time.time())
    return {
        n: t for n, t in used_nonces.items()
        if current_time - t < 600
    }


# ============================================================
# Hash de contrasenas (PBKDF2 + salt)
# ============================================================

def hash_password(password: str) -> tuple:
    """Hashea password con PBKDF2-HMAC-SHA256 + salt aleatorio."""
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return pw_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verifica password contra hash almacenado (tiempo constante)."""
    salt = bytes.fromhex(salt_hex)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(pw_hash.hex(), stored_hash)


# ============================================================
# Empaquetado / desempaquetado de mensajes
# ============================================================

def pack_message(payload: str, key: bytes, seq: int) -> str:
    """Empaqueta mensaje con MAC + NONCE + SEQ."""
    nonce = generate_nonce()
    mac = generate_mac(payload, nonce, seq, key)
    return f"{payload}{SEPARATOR}{mac}{SEPARATOR}{nonce}{SEPARATOR}{seq}"


def unpack_message(raw: str) -> tuple:
    """Desempaqueta mensaje. Retorna (payload, mac, nonce, seq) o None si formato invalido."""
    parts = raw.split(SEPARATOR)
    if len(parts) != 4:
        return None
    try:
        payload, mac, nonce, seq = parts[0], parts[1], parts[2], int(parts[3])
        return payload, mac, nonce, seq
    except (ValueError, IndexError):
        return None
