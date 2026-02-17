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
# Tema 2: se usan claves robustas de 256 bits y derivacion
# por sesion para que comprometer una sesion no afecte a otras.
# ============================================================

def hkdf_derive_key(master_key: bytes, salt: bytes, info: bytes = b"session_key", length: int = 32) -> bytes:
    """
    Deriva una clave de sesion usando HKDF (RFC 5869).
    Proceso extract-then-expand:
      1. Extract: PRK = HMAC-SHA256(salt, master_key) - concentra la entropia
      2. Expand: genera material de clave del tamano deseado a partir de PRK
    Cada sesion usa un salt aleatorio distinto, produciendo claves unicas.
    """
    # Extract: extrae entropia de la master key usando el salt
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    # Expand: expande el PRK al tamano de clave deseado (32 bytes = 256 bits)
    t = b""
    okm = b""
    for i in range(1, (length // 32) + 2):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def generate_session_key(session_salt: bytes = None) -> tuple:
    """Genera una clave de sesion de 256 bits derivada de la master key con un salt aleatorio."""
    if session_salt is None:
        session_salt = os.urandom(16)  # 16 bytes aleatorios como salt
    session_key = hkdf_derive_key(MASTER_KEY, session_salt)
    return session_key, session_salt


# ============================================================
# MAC - HMAC-SHA256 (contra MiTM)
# MAC(M, K) -> Tag T. Proporciona integridad y
# autenticacion de origen. Se usa HMAC (variante basada en hash).
# El MAC incluye nonce y seq para vincularlos al mensaje.
# ============================================================

def generate_mac(message: str, nonce: str, seq: int, key: bytes) -> str:
    """Genera HMAC-SHA256 sobre (mensaje + nonce + seq) con la clave de sesion."""
    data = f"{message}{nonce}{seq}".encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_mac(message: str, nonce: str, seq: int, received_mac: str, key: bytes) -> bool:
    """
    Verifica MAC con comparacion en tiempo constante.
    Tema 2 - Lateral Channel: hmac.compare_digest() recorre siempre
    todos los bytes, evitando que un atacante deduzca informacion
    midiendo tiempos de respuesta.
    """
    expected_mac = generate_mac(message, nonce, seq, key)
    return hmac.compare_digest(expected_mac, received_mac)


# ============================================================
# NONCE con timestamp (contra Replay)
# Tema 2: el replay attack consiste en reenviar un mensaje
# valido capturado. El NONCE (Number used ONCE) garantiza que
# cada mensaje es unico. El timestamp anade una ventana temporal
# para evitar ataques diferidos (timing modification).
# ============================================================

def generate_nonce() -> str:
    """Genera nonce unico: UUID4 (aleatoriedad) + timestamp unix (componente temporal)."""
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
    Valida un nonce contra replay. Retorna (valido, razon_error).
    Doble comprobacion:
      1. Ventana temporal: el timestamp debe estar dentro de NONCE_WINDOW_SECONDS (5 min)
      2. Unicidad: el nonce no debe haberse usado antes en esta ventana
    """
    # Verificar timestamp dentro de ventana (contra timing modification)
    nonce_time = parse_nonce_timestamp(nonce)
    current_time = int(time.time())

    if abs(current_time - nonce_time) > NONCE_WINDOW_SECONDS:
        return False, "Nonce fuera de ventana temporal"

    # Verificar no repetido (contra replay attack)
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
# Tema 2 - Password Integrity & Confidentiality:
#   1. Nunca almacenar passwords en texto plano
#   2. Salting: salt aleatorio por usuario evita tablas rainbow
#      (recomendacion minima 8 bytes, aqui usamos 16 bytes)
#   3. Key Stretching: PBKDF2 con 100.000 iteraciones hace
#      que cada intento de fuerza bruta sea costoso
# ============================================================

def hash_password(password: str) -> tuple:
    """
    Hashea password con PBKDF2-HMAC-SHA256 + salt aleatorio.
    El salt de 16 bytes (128 bits) se genera aleatoriamente por cada usuario,
    asegurando que el mismo password produce hashes distintos.
    """
    salt = os.urandom(16)  # Salt aleatorio de 16 bytes (Tema 2: minimo 8 bytes)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS  # 100.000 iteraciones (key stretching)
    )
    return pw_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """
    Verifica password contra hash almacenado.
    Usa hmac.compare_digest() para comparacion en tiempo constante
    (Tema 2: proteccion contra canal lateral de tiempo).
    """
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
# Formato del protocolo: payload || MAC || NONCE || SEQ
# Tema 2: Mensaje + MAC + NONCE es el esquema recomendado
# para garantizar integridad y evitar replay en transmision.
# ============================================================

def pack_message(payload: str, key: bytes, seq: int) -> str:
    """Empaqueta mensaje con MAC + NONCE + SEQ para transmision segura."""
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
