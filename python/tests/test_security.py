"""
Tests de seguridad para INTEGRIDOS.
Verifican los mecanismos criptograficos del Tema 2:
- MAC (integridad en transmision, contra MiTM)
- NONCE (contra replay attack)
- PBKDF2 + salt (password integrity, key stretching)
- HKDF (derivacion de claves de sesion)
- Comparacion en tiempo constante (contra canal lateral)
"""
import sys
import os
import time

# Anadir directorio padre al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import (
    generate_mac, verify_mac, generate_nonce, is_nonce_valid,
    hash_password, verify_password, hkdf_derive_key,
    pack_message, unpack_message, generate_session_key
)


def test_mac_valid():
    """Tema 2 - MAC: un mensaje legitimo con MAC correcto debe aceptarse."""
    key = os.urandom(32)
    msg = "TRANSACTION|ES123|ES456|200.00"
    nonce = generate_nonce()
    seq = 0
    mac = generate_mac(msg, nonce, seq, key)
    assert verify_mac(msg, nonce, seq, mac, key), "MAC valido deberia verificarse"
    print("[PASS] test_mac_valid")


def test_mac_tampered_message():
    """Tema 2 - Content modification / MiTM: si un atacante altera el mensaje, el MAC falla."""
    key = os.urandom(32)
    msg_original = "TRANSACTION|ES123|ES456|200.00"
    msg_alterado = "TRANSACTION|ES123|ES456|2000.00"  # Atacante cambia cantidad
    nonce = generate_nonce()
    seq = 0
    mac = generate_mac(msg_original, nonce, seq, key)
    assert not verify_mac(msg_alterado, nonce, seq, mac, key), "MAC con mensaje alterado deberia fallar"
    print("[PASS] test_mac_tampered_message (MiTM detectado)")


def test_mac_wrong_key():
    """Tema 2 - Key replication: MAC con clave distinta debe rechazarse."""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    msg = "LOGIN|admin|hash123"
    nonce = generate_nonce()
    seq = 0
    mac = generate_mac(msg, nonce, seq, key1)
    assert not verify_mac(msg, nonce, seq, mac, key2), "MAC con clave distinta deberia fallar"
    print("[PASS] test_mac_wrong_key")


def test_nonce_replay():
    """Tema 2 - Replay attack: un nonce ya usado debe rechazarse."""
    nonce = generate_nonce()
    used_nonces = {nonce: int(time.time())}
    valid, reason = is_nonce_valid(nonce, used_nonces)
    assert not valid, "Nonce repetido deberia rechazarse"
    assert "replay" in reason.lower(), f"Razon deberia mencionar replay: {reason}"
    print("[PASS] test_nonce_replay (Replay detectado)")


def test_nonce_expired():
    """Tema 2 - Timing modification: nonce con timestamp fuera de ventana debe rechazarse."""
    # Crear nonce con timestamp de hace 10 minutos
    old_nonce = f"abc123-{int(time.time()) - 600}"
    used_nonces = {}
    valid, reason = is_nonce_valid(old_nonce, used_nonces)
    assert not valid, "Nonce expirado deberia rechazarse"
    print("[PASS] test_nonce_expired")


def test_nonce_valid():
    """Nonce nuevo y dentro de ventana debe aceptarse."""
    nonce = generate_nonce()
    used_nonces = {}
    valid, reason = is_nonce_valid(nonce, used_nonces)
    assert valid, f"Nonce nuevo deberia aceptarse: {reason}"
    print("[PASS] test_nonce_valid")


def test_password_hash_verify():
    """Tema 2 - Password integrity: password hasheada con PBKDF2 + salt debe verificarse."""
    password = "miPasswordSegura123!"
    pw_hash, salt = hash_password(password)
    assert verify_password(password, pw_hash, salt), "Password correcta deberia verificarse"
    print("[PASS] test_password_hash_verify")


def test_password_hash_wrong():
    """Password incorrecta debe fallar verificacion."""
    pw_hash, salt = hash_password("correcta")
    assert not verify_password("incorrecta", pw_hash, salt), "Password incorrecta deberia fallar"
    print("[PASS] test_password_hash_wrong")


def test_password_hash_unique_salts():
    """Tema 2 - Salting: cada hash debe usar salt diferente (evita tablas rainbow)."""
    _, salt1 = hash_password("misma_password")
    _, salt2 = hash_password("misma_password")
    assert salt1 != salt2, "Salts deben ser diferentes cada vez"
    print("[PASS] test_password_hash_unique_salts")


def test_hkdf_different_salts():
    """Tema 2 - Key derivation: HKDF con salts diferentes produce claves diferentes (aislamiento de sesion)."""
    master = os.urandom(32)
    key1 = hkdf_derive_key(master, os.urandom(16))
    key2 = hkdf_derive_key(master, os.urandom(16))
    assert key1 != key2, "Claves derivadas con salts distintos deben ser diferentes"
    print("[PASS] test_hkdf_different_salts")


def test_hkdf_deterministic():
    """HKDF es determinista: mismo salt + misma master key = misma clave de sesion."""
    master = os.urandom(32)
    salt = os.urandom(16)
    key1 = hkdf_derive_key(master, salt)
    key2 = hkdf_derive_key(master, salt)
    assert key1 == key2, "Misma master key + salt debe dar misma clave"
    print("[PASS] test_hkdf_deterministic")


def test_pack_unpack():
    """Tema 2 - Mensaje + MAC + NONCE: empaquetado/desempaquetado debe ser consistente."""
    key = os.urandom(32)
    payload = "LOGIN|admin|hash123"
    packed = pack_message(payload, key, 0)
    unpacked = unpack_message(packed)
    assert unpacked is not None, "Unpack no deberia fallar"
    p, mac, nonce, seq = unpacked
    assert p == payload, "Payload debe mantenerse"
    assert seq == 0, "Seq debe mantenerse"
    assert verify_mac(p, nonce, seq, mac, key), "MAC debe verificarse tras unpack"
    print("[PASS] test_pack_unpack")


def test_sequence_number_mismatch():
    """Tema 2 - Sequence modification: MAC con numero de secuencia incorrecto debe fallar."""
    key = os.urandom(32)
    msg = "TRANSACTION|ES123|ES456|100"
    nonce = generate_nonce()
    mac = generate_mac(msg, nonce, 0, key)
    assert not verify_mac(msg, nonce, 1, mac, key), "Seq incorrecto deberia invalidar MAC"
    print("[PASS] test_sequence_number_mismatch")


# ============================================================
# Ejecutar todos los tests
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("  TESTS DE SEGURIDAD - INTEGRIDOS")
    print("=" * 50)
    print()

    tests = [
        test_mac_valid,
        test_mac_tampered_message,
        test_mac_wrong_key,
        test_nonce_replay,
        test_nonce_expired,
        test_nonce_valid,
        test_password_hash_verify,
        test_password_hash_wrong,
        test_password_hash_unique_salts,
        test_hkdf_different_salts,
        test_hkdf_deterministic,
        test_pack_unpack,
        test_sequence_number_mismatch,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1

    print()
    print(f"Resultado: {passed}/{len(tests)} tests pasados")
    if failed == 0:
        print("Todos los tests OK!")
    else:
        print(f"{failed} tests fallaron")
