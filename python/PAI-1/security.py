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


# Genera una tupla con el hash de las contraseñas (PBKDF2, salt).
def hash_password(password: str) -> tuple:
    salt = os.urandom(16)  # Genera Salt aleatorio por usuario de 16 bytes (inutiliza las tablas rainbow).
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS  # Aplica 100.000 iteraciones (key stretching).
    )
    return pw_hash.hex(), salt.hex()

# Compara el hash resultante con el guardado cuando el usuario se registró.
def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    # Usa hmac.compare_digest() para comparacion en tiempo constante (Secure Comparator).
    salt = bytes.fromhex(salt_hex) # Recupera el Salt original del usuario.
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS # Aplica 100.000 iteraciones (key stretching).
    )
    # Secure Comparator: comparacion en tiempo constante contra Lateral Channel.
    return hmac.compare_digest(pw_hash.hex(), stored_hash) 


# Prepara un mensaje para enviarlo por la red (payload || MAC || NONCE). 
def pack_message(payload: str, key: bytes) -> str:
    nonce = generate_nonce() # Genera un NONCE único para este mensaje (UUID4 + timestamp).
    mac = generate_mac(payload, nonce, key) # Calcula el MAC sobre el payload + NONCE usando la clave maestra
    return f"{payload}{SEPARATOR}{mac}{SEPARATOR}{nonce}"


# Desmonta un mensaje recibido.
def unpack_message(raw: str) -> tuple:
    parts = raw.split(SEPARATOR)
    if len(parts) != 3:
        return None
    try:
        payload, mac, nonce = parts[0], parts[1], parts[2]
        return payload, mac, nonce
    except (ValueError, IndexError):
        return None


# Genera NONCE unico: UUID4 (aleatorio) + timestamp (tiempo).
def generate_nonce() -> str:
    return f"{uuid.uuid4().hex}-{int(time.time())}"


# Extrae el timestamp de un NONCE.
def parse_nonce_timestamp(nonce: str) -> int:
    try:
        return int(nonce.split("-")[-1])
    except (ValueError, IndexError):
        return 0


# Carga NONCEs usados desde fichero.
def load_used_nonces() -> dict:
    if os.path.exists(NONCES_FILE):
        with open(NONCES_FILE, "r") as f:
            return json.load(f)
    return {}


# Guarda NONCEs usados en fichero.
def save_used_nonces(nonces: dict):
    with open(NONCES_FILE, "w") as f:
        json.dump(nonces, f)


# Valida un NONCE contra Replay. Devuelve una tupla con la validez y el motivo del error
def is_nonce_valid(nonce: str, used_nonces: dict) -> tuple:
    # Verificar timestamp dentro de ventana (contra timing modification, de 5 mins en nuestro caso)
    nonce_time = parse_nonce_timestamp(nonce)
    current_time = int(time.time())

    if abs(current_time - nonce_time) > NONCE_WINDOW_SECONDS:
        return False, "Nonce fuera de ventana temporal"

    # Verificar no repetido (contra replay attack), verifica que es único el NONCE.
    if nonce in used_nonces:
        return False, "Nonce ya utilizado (posible replay)"

    return True, "OK"


# Elimina NONCEs con más de 10 minutos
def cleanup_old_nonces(used_nonces: dict) -> dict:
    current_time = int(time.time())
    return {
        n: t for n, t in used_nonces.items()
        if current_time - t < 600
    }


# Genera HMAC-SHA256 sobre (mensaje + nonce) con la clave maestra.
def generate_mac(message: str, nonce: str, key: bytes) -> str:
    data = f"{message}{nonce}".encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# Verifica MAC aplicando una comparación en tiempo constante.
def verify_mac(message: str, nonce: str, received_mac: str, key: bytes) -> bool:
    expected_mac = generate_mac(message, nonce, key)
    # Secure Comparator: comparacion en tiempo constante contra Lateral Channel.
    return hmac.compare_digest(expected_mac, received_mac)
