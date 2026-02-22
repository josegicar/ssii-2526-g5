import socket
import json
import os
import threading
import logging
import time

from config import (
    HOST, PORT, BUFFER_SIZE, FIELD_SEPARATOR,
    USERS_FILE, TRANSACTIONS_FILE,
    MAX_MESSAGE_SIZE, MASTER_KEY,
    DATA_DIR, LOGS_DIR
)
from security import (
    verify_mac, is_nonce_valid,
    load_used_nonces, save_used_nonces, cleanup_old_nonces,
    hash_password, verify_password,
    pack_message, unpack_message
)

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

file_lock = threading.Lock()


# --- Persistencia JSON ---

def load_json(filepath, default):
    if not os.path.exists(filepath):
        return default
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(filepath, data):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def load_users():
    with file_lock:
        return load_json(USERS_FILE, {})

def save_users(users):
    with file_lock:
        save_json(USERS_FILE, users)

def load_transactions():
    with file_lock:
        return load_json(TRANSACTIONS_FILE, [])

def save_transactions(transactions):
    with file_lock:
        save_json(TRANSACTIONS_FILE, transactions)


# --- Usuarios preexistentes ---

def init_preexisting_users():
    users = load_users()
    if users:
        return
    for username, password in [("admin", "admin1234"), ("usuario1", "pass1234"), ("usuario2", "segura5678")]:
        pw_hash, salt = hash_password(password)
        users[username] = {"password_hash": pw_hash, "salt": salt}
    save_users(users)
    logger.info("Usuarios preexistentes creados")


# --- Manejo de cliente ---

def handle_client(conn: socket.socket, addr: tuple):
    client_ip = addr[0]
    logger.info(f"Conexion desde {addr}")
    used_nonces = load_used_nonces()
    logged_in_user = None

    def send(payload):
        response = pack_message(payload, MASTER_KEY)
        conn.sendall((response + "\n").encode("utf-8"))

    try:
        while True:
            raw = conn.recv(BUFFER_SIZE).decode("utf-8").strip()
            if not raw:
                break

            if len(raw) > MAX_MESSAGE_SIZE:
                send("ERROR|Mensaje demasiado grande")
                continue

            unpacked = unpack_message(raw)
            if unpacked is None:
                send("ERROR|Formato de mensaje invalido")
                continue

            payload, mac, nonce = unpacked

            # Verificar MAC (contra MiTM)
            if not verify_mac(payload, nonce, mac, MASTER_KEY):
                logger.warning(f"[{addr}] MAC invalido - posible MiTM")
                send("ERROR|MAC invalido - mensaje rechazado")
                continue

            # Verificar NONCE (contra Replay)
            nonce_valid, nonce_reason = is_nonce_valid(nonce, used_nonces)
            if not nonce_valid:
                logger.warning(f"[{addr}] NONCE rechazado: {nonce_reason}")
                send(f"ERROR|{nonce_reason}")
                continue

            used_nonces[nonce] = int(time.time())
            used_nonces = cleanup_old_nonces(used_nonces)
            save_used_nonces(used_nonces)

            fields = payload.split(FIELD_SEPARATOR)
            command = fields[0]
            response_payload = process_command(command, fields, client_ip, logged_in_user)

            if command == "LOGIN" and response_payload.startswith("OK"):
                logged_in_user = fields[1]
            elif command == "LOGOUT":
                logged_in_user = None

            send(response_payload)

    except ConnectionResetError:
        logger.info(f"[{addr}] Conexion cerrada por el cliente")
    except Exception as e:
        logger.error(f"[{addr}] Error: {e}")
    finally:
        conn.close()
        logger.info(f"[{addr}] Conexion finalizada")


def process_command(command: str, fields: list, client_ip: str, logged_in_user: str) -> str:
    if command == "REGISTER":
        return handle_register(fields)
    elif command == "LOGIN":
        return handle_login(fields, client_ip)
    elif command == "TRANSACTION":
        return handle_transaction(fields, logged_in_user)
    elif command == "LOGOUT":
        return handle_logout(logged_in_user)
    return "ERROR|Comando desconocido"


def handle_register(fields: list) -> str:
    if len(fields) != 3:
        return "ERROR|Formato: REGISTER|username|password"
    username, password = fields[1], fields[2]
    users = load_users()
    if username in users:
        return "ERROR|El usuario ya existe"
    pw_hash, salt = hash_password(password)
    users[username] = {"password_hash": pw_hash, "salt": salt}
    save_users(users)
    logger.info(f"Usuario '{username}' registrado")
    return "OK|Usuario registrado correctamente"


def handle_login(fields: list, client_ip: str) -> str:
    if len(fields) != 3:
        return "ERROR|Formato: LOGIN|username|password"
    username, password = fields[1], fields[2]
    users = load_users()
    user = users.get(username)
    if not user or not verify_password(password, user["password_hash"], user["salt"]):
        logger.warning(f"Login fallido para '{username}' (IP: {client_ip})")
        return "ERROR|Credenciales incorrectas"
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
    transactions.append({
        "usuario": logged_in_user,
        "cuenta_origen": cuenta_orig,
        "cuenta_destino": cuenta_dest,
        "cantidad": cantidad,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    save_transactions(transactions)
    logger.info(f"Transaccion: {cuenta_orig} -> {cuenta_dest}: {cantidad}EUR")
    return f"OK|Transaccion registrada: {cuenta_orig} -> {cuenta_dest}: {cantidad} EUR"


def handle_logout(logged_in_user: str) -> str:
    if logged_in_user is None:
        return "ERROR|No hay sesion activa"
    logger.info(f"Logout: '{logged_in_user}'")
    return f"OK|Sesion de {logged_in_user} cerrada"


# --- Main ---

def main():
    init_preexisting_users()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    logger.info(f"Servidor escuchando en {HOST}:{PORT}")
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Servidor detenido")
    finally:
        server.close()


if __name__ == "__main__":
    main()
