import socket
import logging
import os
import time

from config import HOST, PORT, BUFFER_SIZE, FIELD_SEPARATOR, LOGS_DIR, MASTER_KEY
from security import pack_message, unpack_message, verify_mac, is_nonce_valid

os.makedirs(LOGS_DIR, exist_ok=True)

# NONCEs recibidos del servidor en esta sesion (contra replay de respuestas).
_client_used_nonces = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "client.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("client")


# Envia un mensaje firmado y verifica el MAC de la respuesta (bidireccional contra MiTM).
def send_secure(sock: socket.socket, payload: str) -> str:
    sock.sendall((pack_message(payload, MASTER_KEY) + "\n").encode("utf-8"))

    raw = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
    if not raw:
        return None

    unpacked = unpack_message(raw)
    if unpacked is None:
        logger.warning("Respuesta del servidor con formato invalido")
        return None

    resp_payload, resp_mac, resp_nonce = unpacked

    # Secure Comparator: verifica MAC de la respuesta contra MiTM.
    if not verify_mac(resp_payload, resp_nonce, resp_mac, MASTER_KEY):
        logger.warning("MAC de respuesta INVALIDO - posible MiTM")
        print("\n[!] ALERTA: MAC invalido en respuesta del servidor. Posible MiTM.\n")
        return None

    # Verifica NONCE de la respuesta contra Replay (lado cliente).
    nonce_valid, nonce_reason = is_nonce_valid(resp_nonce, _client_used_nonces)
    if not nonce_valid:
        logger.warning(f"NONCE de respuesta invalido: {nonce_reason}")
        print(f"\n[!] ALERTA: {nonce_reason} en respuesta del servidor. Posible Replay.\n")
        return None
    _client_used_nonces[resp_nonce] = int(time.time())

    return resp_payload


def print_response(response: str, accion: str):
    if response:
        parts = response.split(FIELD_SEPARATOR, 1)
        print(f"[{parts[0]}] {parts[1] if len(parts) > 1 else ''}")
        logger.info(f"{accion}: {response}")


def do_register(sock):
    print("\n--- REGISTRO ---")
    username = input("Nombre de usuario: ").strip()
    password = input("Contrasena: ").strip()
    if not username or not password:
        print("Usuario y contrasena no pueden estar vacios.")
        return
    print_response(send_secure(sock, f"REGISTER{FIELD_SEPARATOR}{username}{FIELD_SEPARATOR}{password}"), "Registro")


def do_login(sock):
    print("\n--- INICIO DE SESION ---")
    username = input("Nombre de usuario: ").strip()
    password = input("Contrasena: ").strip()
    if not username or not password:
        print("Usuario y contrasena no pueden estar vacios.")
        return
    print_response(send_secure(sock, f"LOGIN{FIELD_SEPARATOR}{username}{FIELD_SEPARATOR}{password}"), "Login")


def do_transaction(sock):
    print("\n--- NUEVA TRANSACCION ---")
    cuenta_orig = input("Cuenta origen: ").strip()
    cuenta_dest = input("Cuenta destino: ").strip()
    cantidad = input("Cantidad (EUR): ").strip()
    if not cuenta_orig or not cuenta_dest or not cantidad:
        print("Todos los campos son obligatorios.")
        return
    print_response(send_secure(sock, f"TRANSACTION{FIELD_SEPARATOR}{cuenta_orig}{FIELD_SEPARATOR}{cuenta_dest}{FIELD_SEPARATOR}{cantidad}"), "Transaccion")


def do_logout(sock):
    print_response(send_secure(sock, "LOGOUT"), "Logout")


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
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        logger.info(f"Conectado a {HOST}:{PORT}")
        print(f"Conectado al servidor {HOST}:{PORT}\n")

        while True:
            show_menu()
            option = input("Seleccione opcion: ").strip()
            if option == "1":
                do_register(sock)
            elif option == "2":
                do_login(sock)
            elif option == "3":
                do_transaction(sock)
            elif option == "4":
                do_logout(sock)
            elif option == "5":
                print("Desconectando...")
                break
            else:
                print("Opcion no valida.")

    except ConnectionRefusedError:
        print(f"Error: No se pudo conectar a {HOST}:{PORT}. Asegurese de que el servidor esta en ejecucion.")
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"Error: {e}")
    finally:
        sock.close()
        logger.info("Conexion cerrada")
        print("Conexion cerrada.")


if __name__ == "__main__":
    main()
