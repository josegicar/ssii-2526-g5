# PAI-1: INTEGRIDOS

Verificadores de Integridad en la Transmision Punto-Punto para Entidad Financiera.

Proyecto de la asignatura Seguridad en Sistemas Informaticos e Internet (SSII) - Universidad de Sevilla.

## Descripcion

Sistema cliente-servidor que permite a una entidad financiera realizar transacciones electronicas a traves de una red publica, garantizando la **integridad** de todas las comunicaciones mediante mecanismos criptograficos.

El sistema implementa:
- Registro e inicio de sesion de usuarios
- Transacciones bancarias (cuenta origen, cuenta destino, cantidad)
- Persistencia de datos (usuarios y transacciones)
- Verificacion de integridad en transmision y almacenamiento

## Arquitectura

```
+----------+                    Red publica                    +----------+
|          |  mensaje + MAC + NONCE + SEQ                      |          |
| Cliente  | --------------------------------------------->    | Servidor |
|  (CLI)   |                                                   |          |
|          |  <---------------------------------------------   |  datos/  |
|          |  respuesta + MAC + NONCE + SEQ                    | *.json   |
+----------+                                                   +----------+
     |                                                              |
     | Clave de sesion                                              | Clave de sesion
     | derivada con HKDF                                            | derivada con HKDF
     |                                                              |
     +------- Master Key (compartida via .env) --------------------+
```

### Componentes

| Fichero | Funcion |
|---------|---------|
| `python/config.py` | Configuracion: puerto, rutas, constantes de seguridad |
| `python/security.py` | Funciones criptograficas: HMAC, HKDF, NONCE, PBKDF2 |
| `python/server.py` | Servidor socket multihilo con logica de negocio |
| `python/client.py` | Cliente CLI con menu interactivo |
| `python/tests/test_security.py` | 13 tests unitarios de seguridad |
| `python/.env` | Clave maestra (no se sube al repositorio) |

### Protocolo de mensajes

Cada mensaje (en ambas direcciones) se envia con el formato:

```
payload||HMAC-SHA256(payload + nonce + seq, clave_sesion)||nonce||seq
```

Donde:
- **payload**: tipo de operacion y datos (ej: `REGISTER|usuario|hash_password`)
- **HMAC**: codigo de autenticacion del mensaje
- **nonce**: UUID4 + timestamp unix (valor de un solo uso)
- **seq**: numero de secuencia incremental

## Amenazas y soluciones

### 1. Man-in-the-Middle (MiTM)

**Amenaza**: un atacante intercepta el mensaje y modifica su contenido (ej: cambiar la cantidad de una transferencia de 200 a 2000 EUR).

**Solucion**: cada mensaje incluye un **HMAC-SHA256** calculado con una clave secreta compartida. Si el atacante modifica el mensaje, el MAC no coincidira y el servidor rechazara el mensaje. La verificacion es **bidireccional**: el cliente tambien verifica las respuestas del servidor.

- Implementacion: `security.py` -> `generate_mac()`, `verify_mac()`
- Algoritmo: HMAC-SHA256 (RFC 2104)
- Clave: 256 bits derivada por sesion

### 2. Replay Attack

**Amenaza**: un atacante captura un mensaje valido (con su MAC correcto) y lo reenvia posteriormente para duplicar una transaccion.

**Solucion**: cada mensaje incluye un **NONCE** (numero de un solo uso) compuesto por UUID4 + timestamp. El servidor:
- Almacena los nonces ya usados y rechaza cualquier nonce repetido
- Rechaza mensajes cuyo timestamp este fuera de una ventana de 5 minutos
- Verifica el **numero de secuencia** (seq) incremental por sesion

- Implementacion: `security.py` -> `generate_nonce()`, `is_nonce_valid()`
- Ventana temporal: 300 segundos
- Limpieza automatica de nonces antiguos (>10 min)

### 3. Key Derivation Attack

**Amenaza**: un atacante intenta derivar o adivinar la clave criptografica utilizada.

**Solucion**:
- La clave maestra es de **256 bits** (32 bytes)
- Se usa **HKDF** (RFC 5869) para derivar una clave unica por sesion a partir de la master key + un salt aleatorio
- La clave maestra se almacena en fichero `.env` fuera del codigo fuente
- Las contrasenas se almacenan con **PBKDF2-HMAC-SHA256** con salt aleatorio y 100.000 iteraciones

- Implementacion: `security.py` -> `hkdf_derive_key()`, `hash_password()`

### 4. Canal lateral (Timing Attack)

**Amenaza**: un atacante mide el tiempo de respuesta del servidor para deducir informacion sobre las credenciales (ej: saber si un caracter del MAC es correcto).

**Solucion**: todas las comparaciones de valores criptograficos (MAC y hashes de contrasena) se realizan con `hmac.compare_digest()`, que opera en **tiempo constante** independientemente de en que posicion difieran los valores.

- Implementacion: `security.py` -> `verify_mac()`, `verify_password()`

### 5. Fuerza bruta

**Amenaza**: un atacante intenta multiples combinaciones de credenciales.

**Solucion**: **rate limiting** que bloquea la IP tras 5 intentos fallidos durante 30 segundos. Todos los intentos fallidos se registran en el log.

- Implementacion: `server.py` -> `check_rate_limit()`, `record_failed_login()`

### 6. Manipulacion de ficheros de datos

**Amenaza**: un atacante con acceso al servidor modifica directamente los ficheros JSON (ej: anade un usuario o altera transacciones).

**Solucion**: cada fichero JSON tiene un fichero `.hmac` asociado que contiene el HMAC-SHA256 de su contenido. Al cargar los datos, el servidor verifica la integridad y si detecta manipulacion lanza una alerta critica y rechaza la carga.

- Implementacion: `server.py` -> `load_json_secure()`, `save_json_secure()`

## Despliegue y uso

### Requisitos

- Python 3.10 o superior
- No requiere dependencias externas (solo librerias estandar de Python)

### Instalacion

1. Clonar el repositorio:
```bash
git clone <url-del-repositorio>
cd ssii-2526-g5
```

2. Configurar la clave maestra. Crear el fichero `python/.env`:
```
MASTER_KEY=a3f1b2c4d5e6f7081920a1b2c3d4e5f6a7b8c9d0e1f2031415161718191a1b1c
```
La clave debe ser una cadena hexadecimal de 64 caracteres (256 bits). El fichero `.env` debe estar presente tanto en la maquina del servidor como en la del cliente, con la misma clave.

### Ejecucion

**Terminal 1 - Arrancar el servidor:**
```bash
cd python
python server.py
```

El servidor:
- Crea los usuarios preexistentes (admin, usuario1, usuario2) si es la primera vez
- Escucha en `127.0.0.1:3030`
- Registra toda la actividad en `logs/server.log`

**Terminal 2 - Arrancar el cliente:**
```bash
cd python
python client.py
```

El cliente muestra un menu interactivo:
```
========================================
  INTEGRIDOS - Entidad Financiera
========================================
  1. Registrarse
  2. Iniciar sesion
  3. Realizar transaccion
  4. Cerrar sesion
  5. Salir
========================================
```

### Usuarios preexistentes

| Usuario | Contrasena |
|---------|------------|
| admin | admin1234 |
| usuario1 | pass1234 |
| usuario2 | segura5678 |

### Ejecutar tests

```bash
cd python
python tests/test_security.py
```

Ejecuta 13 tests que verifican:
- MAC valido/invalido (deteccion MiTM)
- Nonce repetido (deteccion Replay)
- Nonce expirado (fuera de ventana temporal)
- Hash y verificacion de contrasenas
- Derivacion de claves con HKDF
- Empaquetado/desempaquetado de mensajes
- Numero de secuencia incorrecto

### Estructura de datos

Los datos se almacenan en `python/data/`:
- `users.json` + `users.json.hmac` - Usuarios registrados (solo hashes, nunca contrasenas en claro)
- `transactions.json` + `transactions.json.hmac` - Transacciones realizadas
- `used_nonces.json` - Nonces utilizados (limpieza automatica)

Los logs se almacenan en `python/logs/`:
- `server.log` - Actividad del servidor (conexiones, registros, logins, transacciones, ataques detectados)
- `client.log` - Actividad del cliente

## Equipo

Security Team - Grupo 5 - SSII 2025/2026
