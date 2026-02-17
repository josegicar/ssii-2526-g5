# PAI-1: INTEGRIDOS

Verificadores de Integridad en la Transmision Punto-Punto para Entidad Financiera.

Proyecto de la asignatura Seguridad en Sistemas Informaticos e Internet (SSII) - Universidad de Sevilla.

## En que consiste

Una entidad financiera quiere ofrecer un servicio de transferencias a sus clientes por Internet. El problema es que Internet es una red publica y cualquiera podria interceptar, modificar o reenviar los mensajes. Este es uno de los problemas centrales: como asegurar la **integridad de los datos** tanto en almacenamiento como en transmision.

Este proyecto implementa un sistema cliente-servidor que garantiza la integridad de todas las comunicaciones usando las tecnicas criptograficas vistas en clase: funciones hash seguras (SHA-256), codigos de autenticacion de mensajes (HMAC), nonces contra replay, key stretching para contrasenas (PBKDF2) y comparacion en tiempo constante contra ataques de canal lateral.

En resumen: un cliente se conecta al servidor por sockets, se registra o inicia sesion, y puede hacer transferencias. Todos los mensajes van firmados para que nadie pueda manipularlos.

## Como se ha implementado (paso a paso)

### Punto de partida

Se partia de dos ficheros base proporcionados por el profesorado:
- `clientsocket.py` - Un cliente socket basico que envia un mensaje y recibe la respuesta (eco)
- `serversocket.py` - Un servidor socket basico que recibe un mensaje y lo devuelve tal cual

Estos ficheros solo demuestran como abrir una conexion TCP con sockets en Python. No tienen ninguna seguridad.

### Que se ha construido encima

A partir de esos sockets basicos, se han desarrollado 4 modulos:

1. **`config.py`** - Fichero de configuracion central. Define el puerto, las rutas de los datos, y carga la clave maestra desde un fichero `.env` (nunca hardcodeada en el codigo).

2. **`security.py`** - El nucleo criptografico. Contiene todas las funciones de seguridad que usan tanto el cliente como el servidor:
   - Derivar claves de sesion (HKDF)
   - Firmar mensajes (HMAC-SHA256)
   - Generar y validar nonces (anti-replay)
   - Hashear contrasenas (PBKDF2)
   - Empaquetar/desempaquetar mensajes con su firma

3. **`server.py`** - Servidor multihilo. Acepta conexiones, genera una clave de sesion unica para cada cliente, y valida cada mensaje antes de procesarlo. Gestiona el registro, login, transacciones y logout. Guarda los datos en ficheros JSON protegidos con HMAC.

4. **`client.py`** - Cliente con menu interactivo. Se conecta al servidor, deriva la misma clave de sesion, y firma cada mensaje que envia. Tambien verifica las respuestas del servidor (proteccion bidireccional).

5. **`tests/test_security.py`** - 13 tests unitarios que verifican que todas las protecciones funcionan correctamente.

### Flujo de una conexion

```
1. El servidor arranca y escucha en el puerto 3030
2. El cliente se conecta -> el servidor genera un "salt" aleatorio y se lo envia
3. Ambos derivan la MISMA clave de sesion usando HKDF(clave_maestra + salt)
4. A partir de aqui, cada mensaje viaja asi:
   PAYLOAD || MAC || NONCE || SEQ
5. El servidor valida MAC + NONCE + SEQ antes de procesar cualquier comando
6. Si algo no cuadra, el mensaje se rechaza y se registra en el log
```

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

## Requisitos del enunciado y como se han cumplido

### Requisitos funcionales

| Requisito | Estado | Donde se implementa |
|-----------|--------|---------------------|
| Registro de usuarios | Cumplido | `server.py` -> `handle_register()`, `client.py` -> `do_register()` |
| Inicio de sesion | Cumplido | `server.py` -> `handle_login()`, `client.py` -> `do_login()` |
| Verificacion de credenciales | Cumplido | `security.py` -> `hash_password()`, `verify_password()` |
| Cerrar sesion | Cumplido | `server.py` -> `handle_logout()`, `client.py` -> `do_logout()` |
| Usuarios preexistentes | Cumplido | `server.py` -> `init_preexisting_users()` (admin, usuario1, usuario2) |
| Transacciones (origen, destino, cantidad) | Cumplido | `server.py` -> `handle_transaction()` |
| Persistencia de datos | Cumplido | Ficheros JSON en `python/data/` |
| Comunicacion con sockets | Cumplido | Socket TCP en `client.py` y `server.py` |

### Requisitos de seguridad

| Requisito | Mecanismo usado | Donde se implementa |
|-----------|----------------|---------------------|
| Verificador de integridad (MAC) | HMAC-SHA256 con clave de sesion | `security.py` -> `generate_mac()`, `verify_mac()` |
| Proteccion anti-replay (NONCE) | UUID4 + timestamp + numero de secuencia | `security.py` -> `generate_nonce()`, `is_nonce_valid()` |
| Tamano de clave adecuado | Clave maestra de 256 bits, claves de sesion de 256 bits | `config.py`, `security.py` -> `hkdf_derive_key()` |
| Secure comparator (anti timing) | `hmac.compare_digest()` en todas las comparaciones | `security.py` -> `verify_mac()`, `verify_password()` |
| Almacenamiento seguro de credenciales | PBKDF2-HMAC-SHA256 + salt aleatorio + 100.000 iteraciones | `security.py` -> `hash_password()` |
| Proteccion contra fuerza bruta | Rate limiting: bloqueo de IP tras 5 intentos fallidos | `server.py` -> `check_rate_limit()` |

### Ataques que se previenen

| Ataque | Como se previene |
|--------|-----------------|
| **Man-in-the-Middle** | Cada mensaje lleva un HMAC-SHA256. Si alguien modifica el mensaje, el MAC no coincide y se rechaza |
| **Replay** | Cada mensaje lleva un NONCE unico + timestamp. El servidor rechaza nonces repetidos o fuera de ventana temporal (5 min) |
| **Key derivation** | La clave maestra (256 bits) nunca viaja por la red. Se usa HKDF para derivar claves de sesion unicas |
| **Canal lateral (timing)** | Todas las comparaciones criptograficas usan `hmac.compare_digest()` (tiempo constante) |

## Amenazas y soluciones (detalle tecnico)

### 1. Man-in-the-Middle (MiTM)

**Amenaza**: un atacante intercepta el mensaje y modifica su contenido (ej: cambiar la cantidad de una transferencia de 200 a 2000 EUR). El Tema 2 clasifica esto como **content modification**, una de las amenazas principales en la transmision de datos.

**Solucion**: cada mensaje incluye un **HMAC-SHA256** calculado con una clave secreta compartida (concepto de MAC visto en el Tema 2: el MAC recibe un mensaje M y una clave secreta K, y produce un tag T que permite verificar integridad y autenticacion de origen). Si el atacante modifica el mensaje, el MAC no coincidira y el servidor rechazara el mensaje. La verificacion es **bidireccional**: el cliente tambien verifica las respuestas del servidor.

- Implementacion: `security.py` -> `generate_mac()`, `verify_mac()`
- Algoritmo: HMAC-SHA256 (RFC 2104), variante de MAC basada en hash como se describe en el Tema 2
- Clave: 256 bits derivada por sesion

### 2. Replay Attack

**Amenaza**: un atacante captura un mensaje valido (con su MAC correcto) y lo reenvia posteriormente para duplicar una transaccion. El Tema 2 identifica el **replay attack** como uno de los ataques principales contra MACs y presenta el NONCE como solucion.

**Solucion**: cada mensaje incluye un **NONCE** (numero de un solo uso) compuesto por UUID4 + timestamp, tal como recomienda el Tema 2. El servidor:
- Almacena los nonces ya usados y rechaza cualquier nonce repetido
- Rechaza mensajes cuyo timestamp este fuera de una ventana de 5 minutos (proteccion contra **timing modification**)
- Verifica el **numero de secuencia** (seq) incremental por sesion (proteccion contra **sequence modification**)

Esto cubre tres de las amenazas de transmision listadas en el Tema 2: replay, sequence modification y timing modification.

- Implementacion: `security.py` -> `generate_nonce()`, `is_nonce_valid()`
- Ventana temporal: 300 segundos
- Limpieza automatica de nonces antiguos (>10 min)

### 3. Key Derivation Attack

**Amenaza**: un atacante intenta derivar o adivinar la clave criptografica utilizada. El Tema 2 menciona los ataques de **key replication** y la importancia de usar claves robustas con tamano adecuado.

**Solucion**:
- La clave maestra es de **256 bits** (32 bytes), tamano que el Tema 2 considera adecuado para claves criptograficas
- Se usa **HKDF** (RFC 5869) para derivar una clave unica por sesion a partir de la master key + un salt aleatorio. Esto evita que comprometer una sesion comprometa las demas
- La clave maestra se almacena en fichero `.env` fuera del codigo fuente
- Las contrasenas se almacenan con **PBKDF2-HMAC-SHA256** con salt aleatorio y 100.000 iteraciones (ver seccion de fuerza bruta)

- Implementacion: `security.py` -> `hkdf_derive_key()`, `hash_password()`

### 4. Canal lateral (Timing Attack)

**Amenaza**: un atacante mide el tiempo de respuesta del servidor para deducir informacion sobre las credenciales (ej: saber si un caracter del MAC es correcto). Este es un ataque de **canal lateral** (lateral channel) como se describe en el Tema 2.

**Solucion**: todas las comparaciones de valores criptograficos (MAC y hashes de contrasena) se realizan con `hmac.compare_digest()`, que opera en **tiempo constante** independientemente de en que posicion difieran los valores. Una comparacion normal (`==`) retornaria `False` en cuanto encuentra el primer byte distinto, filtrando informacion sobre cuantos bytes son correctos. La comparacion en tiempo constante siempre recorre todos los bytes antes de devolver el resultado.

- Implementacion: `security.py` -> `verify_mac()`, `verify_password()`

### 5. Fuerza bruta

**Amenaza**: un atacante intenta multiples combinaciones de credenciales.

**Solucion**: se aplican dos medidas complementarias, ambas basadas en conceptos del Tema 2:

1. **Key stretching con PBKDF2**: como explica el Tema 2, las funciones de key stretching (PBKDF2, bcrypt, scrypt, Argon2) hacen que cada intento de verificacion sea computacionalmente costoso. El proyecto usa PBKDF2-HMAC-SHA256 con 100.000 iteraciones y un salt aleatorio de 16 bytes por usuario (el Tema 2 recomienda un minimo de 8 bytes). El salt variable evita ataques con tablas rainbow, ya que el mismo password produce hashes distintos para cada usuario.

2. **Rate limiting**: bloquea la IP tras 5 intentos fallidos durante 30 segundos. Todos los intentos fallidos se registran en el log.

- Implementacion: `security.py` -> `hash_password()`, `verify_password()`; `server.py` -> `check_rate_limit()`, `record_failed_login()`

### 6. Manipulacion de ficheros de datos

**Amenaza**: un atacante con acceso al servidor modifica directamente los ficheros JSON (ej: anade un usuario o altera transacciones).

**Solucion**: cada fichero JSON tiene un fichero `.hmac` asociado que contiene el HMAC-SHA256 de su contenido. Al cargar los datos, el servidor recalcula el hash y lo compara con el almacenado. Si no coinciden, se detecta la manipulacion, se lanza una alerta critica y se rechaza la carga. Este es el mismo principio de **File Integrity Monitoring (FIM)** que describe el Tema 2 con herramientas como Tripwire: comparar hashes actuales contra hashes de referencia para detectar modificaciones no autorizadas. Se usa HMAC en lugar de un hash simple porque incluye una clave secreta, evitando que un atacante recalcule el hash tras modificar el fichero.

- Implementacion: `server.py` -> `load_json_secure()`, `save_json_secure()`, `_file_hmac()`

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

## Grado de completitud

Se han implementado **todos** los requisitos funcionales y de seguridad especificados en el enunciado:

- Todos los requisitos funcionales (registro, login, logout, transacciones, persistencia, usuarios preexistentes)
- Los 4 ataques del enunciado estan cubiertos (MiTM, Replay, Key derivation, Canal lateral)
- Se incluyen protecciones adicionales no requeridas: rate limiting contra fuerza bruta e integridad de ficheros con HMAC
- Se incluyen 13 tests unitarios que verifican cada mecanismo de seguridad
- Toda la actividad queda registrada en logs (`python/logs/`)

## Equipo

Security Team - Grupo 5 - SSII 2025/2026
