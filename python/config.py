import os

# Conexion
HOST = "127.0.0.1"
PORT = 3030

# Clave maestra pre-compartida (256 bits = 32 bytes)
# Se carga desde fichero .env o variable de entorno (NUNCA hardcodeada en codigo)
def _load_master_key():
    # 1. Intentar variable de entorno
    env_key = os.environ.get("MASTER_KEY")
    if env_key:
        return bytes.fromhex(env_key)

    # 2. Intentar fichero .env
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
NONCE_WINDOW_SECONDS = 300  # 5 minutos
PBKDF2_ITERATIONS = 100_000
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 30
MAX_MESSAGE_SIZE = 4096  # Limite de tamano de mensaje (bytes)

# Protocolo
SEPARATOR = "||"
FIELD_SEPARATOR = "|"
BUFFER_SIZE = 4096
