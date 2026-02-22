import os

# Conexion
HOST = "127.0.0.1"
PORT = 3030

# Se carga la clave maestra pre-compartida (256 bits).
def _load_master_key():
    env_key = os.environ.get("MASTER_KEY")
    if env_key:
        return bytes.fromhex(env_key)

    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("MASTER_KEY="):
                    return bytes.fromhex(line.split("=", 1)[1])

    raise RuntimeError("MASTER_KEY no encontrada. Configure .env o variable de entorno.")

MASTER_KEY = _load_master_key()

# Rutas de datos
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
TRANSACTIONS_FILE = os.path.join(DATA_DIR, "transactions.json")
NONCES_FILE = os.path.join(DATA_DIR, "used_nonces.json")

# Seguridad
NONCE_WINDOW_SECONDS = 300      # Ventana temporal de 5 min para validar nonces (contra replay)
PBKDF2_ITERATIONS = 100_000     # Iteraciones de key stretching (Tema 2: hace costoso cada intento)
MAX_LOGIN_ATTEMPTS = 5          # Intentos maximos antes de bloqueo (contra fuerza bruta)
LOCKOUT_SECONDS = 30            # Segundos de bloqueo tras exceder intentos
MAX_MESSAGE_SIZE = 4096         # Limite de tamano de mensaje (bytes)

# Protocolo
SEPARATOR = "||"
FIELD_SEPARATOR = "|"
BUFFER_SIZE = 4096
