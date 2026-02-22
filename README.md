# PAI-1: INTEGRIDOS

Sistema cliente-servidor que garantiza la **integridad** de credenciales y mensajes de transferencias bancarias frente a ataques MiTM y replay.

> Asignatura SSII — Universidad de Sevilla — Grupo 5 — 2025/2026

---

## Requisitos cubiertos

| Requisito | Mecanismo | Archivo |
|-----------|-----------|---------|
| Integridad de mensajes (anti-MiTM) | HMAC-SHA256 bidireccional | `security.py` |
| Anti-replay | NONCE = UUID4 + timestamp, ventana 5 min | `security.py` |
| Almacenamiento seguro de credenciales | PBKDF2-SHA256 + salt aleatorio (16 B, 100k iter.) | `security.py` |
| Anti timing attack (canal lateral) | `hmac.compare_digest()` en MAC y passwords | `security.py` |
| Anti fuerza bruta | Rate limiting: bloqueo IP tras 5 intentos fallidos | `server.py` |
| Clave de tamaño adecuado | MASTER_KEY de 256 bits cargada desde `.env` | `config.py` |
| Registro, login, transacciones, logout | Comandos `REGISTER`, `LOGIN`, `TRANSACTION`, `LOGOUT` | `server.py` / `client.py` |
| Persistencia | JSON en `data/` con lock de concurrencia | `server.py` |
| Auditoría | Logs en `logs/server.log` y `logs/client.log` | ambos |

---

## Protocolo de mensajes

Cada mensaje (en ambas direcciones) tiene el formato:

```
payload || MAC || NONCE
```

- **payload** — comando y datos: `TRANSACTION|ES111|ES222|500.00`
- **MAC** — `HMAC-SHA256(payload + nonce, MASTER_KEY)` en hex
- **NONCE** — `uuid4hex-timestamp_unix` (único por mensaje)

El separador entre partes es `||`; el separador entre campos del payload es `|`.

---

## Diagrama de envío y respuesta

```
CLIENTE                                         SERVIDOR
  │                                                 │
  │  1. pack_message(payload, MASTER_KEY)           │
  │     → genera NONCE                              │
  │     → calcula MAC = HMAC-SHA256(payload+nonce)  │
  │     → empaqueta: payload||MAC||NONCE            │
  │                                                 │
  │ ──── payload||MAC||NONCE ──────────────────────►│
  │                                                 │  2. unpack_message()
  │                                                 │  3. verify_mac()     → rechaza si MAC inválido
  │                                                 │  4. is_nonce_valid() → rechaza si repetido/expirado
  │                                                 │  5. procesa comando
  │                                                 │  6. pack_message(respuesta, MASTER_KEY)
  │                                                 │
  │ ◄─── respuesta||MAC||NONCE ────────────────────-│
  │                                                 │
  │  7. unpack_message()                            │
  │  8. verify_mac()  → alerta si MAC inválido      │
  │  9. muestra respuesta al usuario                │
```

La verificación del MAC es **bidireccional**: el cliente también autentica las respuestas del servidor.

---

## Estructura del proyecto

```
python/
├── config.py          # Configuración: host, puerto, rutas, constantes de seguridad
├── security.py        # Funciones criptográficas: HMAC, NONCE, PBKDF2
├── server.py          # Servidor multihilo con lógica de negocio
├── client.py          # Cliente CLI con menú interactivo
├── .env               # Clave maestra (NO subir al repositorio)
├── data/
│   ├── users.json         # Usuarios: { username: {password_hash, salt} }
│   ├── transactions.json  # Transacciones registradas
│   └── used_nonces.json   # NONCEs usados (limpieza automática >10 min)
├── logs/
│   ├── server.log
│   └── client.log
└── tests/
    └── test_security.py   # 12 tests unitarios de seguridad
```

---

## Despliegue

### Requisitos

- Python 3.10+
- Sin dependencias externas (solo librería estándar)

### 1. Crear el fichero `.env`

Genera una clave maestra aleatoria de 256 bits y crea `python/.env`:

```bash
python -c "import os; print('MASTER_KEY=' + os.urandom(32).hex())"
```

Copia la salida en `python/.env`:

```
MASTER_KEY=<64 caracteres hexadecimales>
```

> ⚠️ El cliente y el servidor deben compartir exactamente la misma `MASTER_KEY`. El fichero `.env` nunca debe subirse al repositorio (está en `.gitignore`).

### 2. Configuración (opcional)

En `config.py` puedes cambiar:

| Constante | Valor por defecto | Descripción |
|-----------|------------------|-------------|
| `HOST` | `127.0.0.1` | IP del servidor |
| `PORT` | `3030` | Puerto TCP |
| `MAX_LOGIN_ATTEMPTS` | `5` | Intentos antes de bloqueo |
| `LOCKOUT_SECONDS` | `30` | Duración del bloqueo (seg) |
| `NONCE_WINDOW_SECONDS` | `300` | Ventana temporal de NONCEs (seg) |

### 3. Arrancar el servidor

```bash
cd python
python server.py
```

El servidor crea automáticamente los usuarios preexistentes en el primer arranque:

| Usuario | Contraseña |
|---------|-----------|
| `admin` | `admin1234` |
| `usuario1` | `pass1234` |
| `usuario2` | `segura5678` |

### 4. Arrancar el cliente

```bash
cd python
python client.py
```

### 5. Ejecutar los tests

```bash
cd python
python tests/test_security.py
```

Resultado esperado: `12/12 tests pasados`.

Los tests cubren: MAC válido/inválido (MiTM), NONCE repetido/expirado (Replay), hash y verificación de contraseñas (BruteForce), empaquetado de mensajes y Secure Comparator (canal lateral).
