import socket
import json
import os
import threading
import logging
import time
import hmac as hmac_mod
import hashlib

from config import (
    HOST, PORT, BUFFER_SIZE, FIELD_SEPARATOR,
    USERS_FILE, TRANSACTIONS_FILE,
    MAX_LOGIN_ATTEMPTS, LOCKOUT_SECONDS,
    MAX_MESSAGE_SIZE, MASTER_KEY,
    DATA_DIR, LOGS_DIR
)
from security import (
    generate_session_key, verify_mac, is_nonce_valid,
    load_used_nonces, save_used_nonces, cleanup_old_nonces,
    hash_password, verify_password,
    pack_message, unpack_message
)

# ============================================================
# Logging
# ============================================================

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "server.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("server")

# ============================================================
# Lock global para acceso concurrente a ficheros
# ============================================================

file_lock = threading.Lock()

# ============================================================
# Integridad de ficheros JSON (HMAC sobre el contenido)
# ============================================================

def _file_hmac(data_bytes: bytes) -> str:
    """Calcula HMAC-SHA256 del contenido de un fichero para verificar integridad."""
    return hmac_mod.new(MASTER_KEY, data_bytes, hashlib.sha256).hexdigest()


def _hmac_path(filepath: str) -> str:
    """Ruta del fichero .hmac asociado."""
    return filepath + ".hmac"


def load_json_secure(filepath, default):
    """Carga JSON verificando integridad con HMAC."""
    if not os.path.exists(filepath):
        return default

    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()

    # Verificar integridad si existe fichero .hmac
    hmac_file = _hmac_path(filepath)
    if os.path.exists(hmac_file):
        with open(hmac_file, "r") as hf:
            stored_hmac = hf.read().strip()
        computed_hmac = _file_hmac(raw.encode("utf-8"))
        if not hmac_mod.compare_digest(stored_hmac, computed_hmac):
            logger.critical(f"INTEGRIDAD VIOLADA en {filepath} - fichero manipulado")
            raise RuntimeError(f"Integridad del fichero {filepath} comprometida")

    return json.loads(raw)


def save_json_secure(filepath, data):
    """Guarda JSON y su HMAC de integridad."""
    raw = json.dumps(data, indent=2, ensure_ascii=False)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(raw)

    # Guardar HMAC del contenido
    computed_hmac = _file_hmac(raw.encode("utf-8"))
    with open(_hmac_path(filepath), "w") as hf:
        hf.write(computed_hmac)


# ============================================================
# Persistencia JSON (con lock y verificacion de integridad)
# ============================================================

def load_users():
    with file_lock:
        return load_json_secure(USERS_FILE, {})


def save_users(users):
    with file_lock:
        save_json_secure(USERS_FILE, users)


def load_transactions():
    with file_lock:
        return load_json_secure(TRANSACTIONS_FILE, [])


def save_transactions(transactions):
    with file_lock:
        save_json_secure(TRANSACTIONS_FILE, transactions)


# ============================================================
# Usuarios preexistentes
# ============================================================

def init_preexisting_users():
    """Crea usuarios iniciales si no existen."""
    users = load_users()
    if users:
        return  # Ya hay usuarios

    preexisting = [
        ("admin", "admin1234"),
        ("usuario1", "pass1234"),
        ("usuario2", "segura5678"),
    ]

    for username, password in preexisting:
        # El cliente envia SHA-256 del password, asi que almacenamos PBKDF2(SHA256(password))
        client_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        pw_hash, salt = hash_password(client_hash)
        users[username] = {
            "password_hash": pw_hash,
            "salt": salt,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    save_users(users)
    logger.info(f"Usuarios preexistentes creados: {[u[0] for u in preexisting]}")


# ============================================================
# Rate limiting
# ============================================================

login_attempts = {}  # {ip: {"count": int, "locked_until": float}}
rate_limit_lock = threading.Lock()


def check_rate_limit(client_ip: str) -> tuple:
    """Retorna (permitido, mensaje)."""
    with rate_limit_lock:
        if client_ip not in login_attempts:
            return True, ""

        info = login_attempts[client_ip]

        if info.get("locked_until", 0) > time.time():
            remaining = int(info["locked_until"] - time.time())
            return False, f"Cuenta bloqueada. Reintente en {remaining}s"

        if info.get("locked_until", 0) <= time.time() and info.get("count", 0) >= MAX_LOGIN_ATTEMPTS:
            login_attempts[client_ip] = {"count": 0}

        return True, ""


def record_failed_login(client_ip: str):
    with rate_limit_lock:
        if client_ip not in login_attempts:
            login_attempts[client_ip] = {"count": 0}

        login_attempts[client_ip]["count"] += 1
        count = login_attempts[client_ip]["count"]

        if count >= MAX_LOGIN_ATTEMPTS:
            login_attempts[client_ip]["locked_until"] = time.time() + LOCKOUT_SECONDS
            logger.warning(f"IP {client_ip} bloqueada por {LOCKOUT_SECONDS}s tras {count} intentos fallidos")


def reset_login_attempts(client_ip: str):
    with rate_limit_lock:
        login_attempts.pop(client_ip, None)


# ============================================================
# Manejo de cliente
# ============================================================

def handle_client(conn: socket.socket, addr: tuple):
    client_ip = addr[0]
    logger.info(f"Conexion establecida desde {addr}")

    # Negociar clave de sesion: enviar salt al cliente
    session_key, session_salt = generate_session_key()
    conn.sendall(session_salt.hex().encode("utf-8") + b"\n")

    used_nonces = load_used_nonces()
    expected_seq = 0
    logged_in_user = None
    server_seq = 0

    try:
        while True:
            raw = conn.recv(BUFFER_SIZE).decode("utf-8").strip()
            if not raw:
                break

            # Verificar limite de tamano de mensaje
            if len(raw) > MAX_MESSAGE_SIZE:
                logger.warning(f"[{addr}] Mensaje excede tamano maximo ({len(raw)} bytes)")
                response = pack_message("ERROR|Mensaje demasiado grande", session_key, server_seq)
                server_seq += 1
                conn.sendall((response + "\n").encode("utf-8"))
                continue

            # Desempaquetar mensaje
            unpacked = unpack_message(raw)
            if unpacked is None:
                logger.warning(f"[{addr}] Mensaje con formato invalido")
                response = pack_message("ERROR|Formato de mensaje invalido", session_key, server_seq)
                server_seq += 1
                conn.sendall((response + "\n").encode("utf-8"))
                continue

            payload, mac, nonce, seq = unpacked

            # Verificar MAC (contra MiTM)
            if not verify_mac(payload, nonce, seq, mac, session_key):
                logger.warning(f"[{addr}] MAC INVALIDO - posible MiTM. Payload: {payload[:50]}")
                response = pack_message("ERROR|MAC invalido - mensaje rechazado", session_key, server_seq)
                server_seq += 1
                conn.sendall((response + "\n").encode("utf-8"))
                continue

            # Verificar NONCE (contra Replay)
            nonce_valid, nonce_reason = is_nonce_valid(nonce, used_nonces)
            if not nonce_valid:
                logger.warning(f"[{addr}] NONCE RECHAZADO: {nonce_reason}")
                response = pack_message(f"ERROR|{nonce_reason}", session_key, server_seq)
                server_seq += 1
                conn.sendall((response + "\n").encode("utf-8"))
                continue

            # Verificar sequence number (contra reordenacion)
            if seq != expected_seq:
                logger.warning(f"[{addr}] SEQ incorrecto: esperado {expected_seq}, recibido {seq}")
                response = pack_message("ERROR|Numero de secuencia incorrecto", session_key, server_seq)
                server_seq += 1
                conn.sendall((response + "\n").encode("utf-8"))
                continue

            # Registrar nonce como usado
            used_nonces[nonce] = int(time.time())
            used_nonces = cleanup_old_nonces(used_nonces)
            save_used_nonces(used_nonces)
            expected_seq += 1

            # Procesar payload
            fields = payload.split(FIELD_SEPARATOR)
            command = fields[0]

            response_payload = process_command(command, fields, client_ip, logged_in_user)

            # Actualizar estado de sesion
            if command == "LOGIN" and response_payload.startswith("OK"):
                logged_in_user = fields[1]
            elif command == "LOGOUT":
                logged_in_user = None

            response = pack_message(response_payload, session_key, server_seq)
            server_seq += 1
            conn.sendall((response + "\n").encode("utf-8"))

    except ConnectionResetError:
        logger.info(f"[{addr}] Conexion cerrada por el cliente")
    except Exception as e:
        logger.error(f"[{addr}] Error: {e}")
    finally:
        conn.close()
        logger.info(f"[{addr}] Conexion finalizada. Usuario: {logged_in_user}")


def process_command(command: str, fields: list, client_ip: str, logged_in_user: str) -> str:
    """Procesa un comando y retorna el payload de respuesta."""

    if command == "REGISTER":
        return handle_register(fields)

    elif command == "LOGIN":
        return handle_login(fields, client_ip)

    elif command == "TRANSACTION":
        return handle_transaction(fields, logged_in_user)

    elif command == "LOGOUT":
        return handle_logout(logged_in_user)

    else:
        return "ERROR|Comando desconocido"


def handle_register(fields: list) -> str:
    if len(fields) != 3:
        return "ERROR|Formato: REGISTER|username|password"

    username, password = fields[1], fields[2]
    users = load_users()

    if username in users:
        logger.info(f"Registro fallido: usuario '{username}' ya existe")
        return "ERROR|El usuario ya existe"

    pw_hash, salt = hash_password(password)
    users[username] = {
        "password_hash": pw_hash,
        "salt": salt,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    save_users(users)
    logger.info(f"Usuario '{username}' registrado exitosamente")
    return "OK|Usuario registrado correctamente"


def handle_login(fields: list, client_ip: str) -> str:
    if len(fields) != 3:
        return "ERROR|Formato: LOGIN|username|password"

    username, password = fields[1], fields[2]

    # Rate limiting
    allowed, msg = check_rate_limit(client_ip)
    if not allowed:
        logger.warning(f"Login bloqueado para IP {client_ip}: {msg}")
        return f"ERROR|{msg}"

    users = load_users()

    if username not in users:
        record_failed_login(client_ip)
        logger.warning(f"Login fallido: usuario '{username}' no existe (IP: {client_ip})")
        return "ERROR|Credenciales incorrectas"

    user = users[username]
    if not verify_password(password, user["password_hash"], user["salt"]):
        record_failed_login(client_ip)
        logger.warning(f"Login fallido: password incorrecta para '{username}' (IP: {client_ip})")
        return "ERROR|Credenciales incorrectas"

    reset_login_attempts(client_ip)
    logger.info(f"Login exitoso: '{username}' desde {client_ip}")
    return f"OK|Bienvenido {username}"


def handle_transaction(fields: list, logged_in_user: str) -> str:
    if logged_in_user is None:
        return "ERROR|Debe iniciar sesion primero"

    if len(fields) != 4:
        return "ERROR|Formato: TRANSACTION|cuenta_origen|cuenta_destino|cantidad"

    cuenta_orig, cuenta_dest, cantidad = fields[1], fields[2], fields[3]

    try:
        float(cantidad)
    except ValueError:
        return "ERROR|Cantidad invalida"

    transactions = load_transactions()
    transaction = {
        "usuario": logged_in_user,
        "cuenta_origen": cuenta_orig,
        "cuenta_destino": cuenta_dest,
        "cantidad": cantidad,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    transactions.append(transaction)
    save_transactions(transactions)

    logger.info(f"Transaccion registrada: {logged_in_user} -> {cuenta_orig} -> {cuenta_dest}: {cantidad}EUR")
    return f"OK|Transaccion registrada: {cuenta_orig} -> {cuenta_dest}: {cantidad} EUR"


def handle_logout(logged_in_user: str) -> str:
    if logged_in_user is None:
        return "ERROR|No hay sesion activa"

    logger.info(f"Logout: '{logged_in_user}'")
    return f"OK|Sesion de {logged_in_user} cerrada"


# ============================================================
# Main
# ============================================================

def main():
    init_preexisting_users()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    logger.info(f"Servidor escuchando en {HOST}:{PORT}")
    logger.info("Esperando conexiones...")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        logger.info("Servidor detenido")
    finally:
        server.close()


if __name__ == "__main__":
    main()
