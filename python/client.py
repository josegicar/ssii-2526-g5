import socket
import hashlib
import logging
import os

from config import HOST, PORT, BUFFER_SIZE, FIELD_SEPARATOR, LOGS_DIR
from security import (
    generate_session_key, pack_message, unpack_message, verify_mac
)

# ============================================================
# Logging
# ============================================================

os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "client.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("client")


# ============================================================
# Comunicacion segura
# ============================================================

def send_secure(sock: socket.socket, payload: str, session_key: bytes, seq: int) -> tuple:
    """Envia mensaje firmado y recibe respuesta verificada. Retorna (respuesta, nuevo_server_seq)."""
    message = pack_message(payload, session_key, seq)
    sock.sendall((message + "\n").encode("utf-8"))

    # Recibir respuesta
    raw = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
    if not raw:
        return None, 0

    unpacked = unpack_message(raw)
    if unpacked is None:
        logger.warning("Respuesta del servidor con formato invalido")
        return None, 0

    resp_payload, resp_mac, resp_nonce, resp_seq = unpacked

    # Verificar MAC de la respuesta del servidor (bidireccional)
    if not verify_mac(resp_payload, resp_nonce, resp_seq, resp_mac, session_key):
        logger.warning("MAC de respuesta del servidor INVALIDO - posible MiTM")
        print("\n[!] ALERTA: La respuesta del servidor tiene MAC invalido.")
        print("[!] Posible ataque Man-in-the-Middle. Conexion no fiable.\n")
        return None, resp_seq

    return resp_payload, resp_seq


# ============================================================
# Funciones del menu
# ============================================================

def do_register(sock, session_key, seq):
    print("\n--- REGISTRO ---")
    username = input("Nombre de usuario: ").strip()
    password = input("Contrasena: ").strip()

    if not username or not password:
        print("Usuario y contrasena no pueden estar vacios.")
        return seq

    # Hashear password antes de enviar (nunca en texto plano por el socket)
    pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    payload = f"REGISTER{FIELD_SEPARATOR}{username}{FIELD_SEPARATOR}{pw_hash}"

    response, _ = send_secure(sock, payload, session_key, seq)
    if response:
        parts = response.split(FIELD_SEPARATOR, 1)
        status = parts[0]
        msg = parts[1] if len(parts) > 1 else ""
        print(f"[{status}] {msg}")
        logger.info(f"Registro: {status} - {msg}")

    return seq + 1


def do_login(sock, session_key, seq):
    print("\n--- INICIO DE SESION ---")
    username = input("Nombre de usuario: ").strip()
    password = input("Contrasena: ").strip()

    if not username or not password:
        print("Usuario y contrasena no pueden estar vacios.")
        return seq

    pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    payload = f"LOGIN{FIELD_SEPARATOR}{username}{FIELD_SEPARATOR}{pw_hash}"

    response, _ = send_secure(sock, payload, session_key, seq)
    if response:
        parts = response.split(FIELD_SEPARATOR, 1)
        status = parts[0]
        msg = parts[1] if len(parts) > 1 else ""
        print(f"[{status}] {msg}")
        logger.info(f"Login: {status} - {msg}")

    return seq + 1


def do_transaction(sock, session_key, seq):
    print("\n--- NUEVA TRANSACCION ---")
    cuenta_orig = input("Cuenta origen: ").strip()
    cuenta_dest = input("Cuenta destino: ").strip()
    cantidad = input("Cantidad (EUR): ").strip()

    if not cuenta_orig or not cuenta_dest or not cantidad:
        print("Todos los campos son obligatorios.")
        return seq

    payload = f"TRANSACTION{FIELD_SEPARATOR}{cuenta_orig}{FIELD_SEPARATOR}{cuenta_dest}{FIELD_SEPARATOR}{cantidad}"

    response, _ = send_secure(sock, payload, session_key, seq)
    if response:
        parts = response.split(FIELD_SEPARATOR, 1)
        status = parts[0]
        msg = parts[1] if len(parts) > 1 else ""
        print(f"[{status}] {msg}")
        logger.info(f"Transaccion: {status} - {msg}")

    return seq + 1


def do_logout(sock, session_key, seq):
    payload = "LOGOUT"
    response, _ = send_secure(sock, payload, session_key, seq)
    if response:
        parts = response.split(FIELD_SEPARATOR, 1)
        status = parts[0]
        msg = parts[1] if len(parts) > 1 else ""
        print(f"[{status}] {msg}")
        logger.info(f"Logout: {status} - {msg}")

    return seq + 1


# ============================================================
# Menu principal
# ============================================================

def show_menu():
    print("\n========================================")
    print("  INTEGRIDOS - Entidad Financiera")
    print("========================================")
    print("  1. Registrarse")
    print("  2. Iniciar sesion")
    print("  3. Realizar transaccion")
    print("  4. Cerrar sesion")
    print("  5. Salir")
    print("========================================")


def main():
    print("Conectando al servidor...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        logger.info(f"Conectado a {HOST}:{PORT}")

        # Recibir salt de sesion del servidor para derivar clave
        salt_hex = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
        session_salt = bytes.fromhex(salt_hex)
        session_key, _ = generate_session_key(session_salt)
        logger.info("Clave de sesion derivada correctamente")

        print(f"Conectado al servidor {HOST}:{PORT}")
        print("Clave de sesion establecida.\n")

        seq = 0

        while True:
            show_menu()
            option = input("Seleccione opcion: ").strip()

            if option == "1":
                seq = do_register(sock, session_key, seq)
            elif option == "2":
                seq = do_login(sock, session_key, seq)
            elif option == "3":
                seq = do_transaction(sock, session_key, seq)
            elif option == "4":
                seq = do_logout(sock, session_key, seq)
            elif option == "5":
                print("Desconectando...")
                break
            else:
                print("Opcion no valida.")

    except ConnectionRefusedError:
        print(f"Error: No se pudo conectar al servidor en {HOST}:{PORT}")
        print("Asegurese de que el servidor esta en ejecucion.")
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"Error: {e}")
    finally:
        sock.close()
        logger.info("Conexion cerrada")
        print("Conexion cerrada.")


if __name__ == "__main__":
    main()
