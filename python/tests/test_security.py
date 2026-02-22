import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import (
    generate_mac, verify_mac,
    generate_nonce, is_nonce_valid,
    hash_password, verify_password,
    pack_message, unpack_message
)
from config import MASTER_KEY


# --- MAC (contra MiTM) ---

def test_mac_valido():
    # Un mensaje con MAC correcto debe verificarse.
    nonce = generate_nonce()
    mac = generate_mac("TRANSACTION|ES123|ES456|200.00", nonce, MASTER_KEY)
    assert verify_mac("TRANSACTION|ES123|ES456|200.00", nonce, mac, MASTER_KEY)
    print("[PASS] test_mac_valido")


def test_mac_mensaje_alterado():
    # Si un atacante (MiTM) modifica el mensaje, el MAC debe fallar.
    nonce = generate_nonce()
    mac = generate_mac("TRANSACTION|ES123|ES456|200.00", nonce, MASTER_KEY)
    assert not verify_mac("TRANSACTION|ES123|ES456|2000.00", nonce, mac, MASTER_KEY)
    print("[PASS] test_mac_mensaje_alterado (MiTM detectado)")


def test_mac_clave_incorrecta():
    # MAC generado con una clave distinta debe ser rechazado (Key derivation).
    clave_falsa = os.urandom(32)
    nonce = generate_nonce()
    mac = generate_mac("LOGIN|admin|pass", nonce, MASTER_KEY)
    assert not verify_mac("LOGIN|admin|pass", nonce, mac, clave_falsa)
    print("[PASS] test_mac_clave_incorrecta")


# --- NONCE (contra Replay) ---

def test_nonce_replay():
    # Un nonce ya utilizado debe ser rechazado para evitar Replay.
    nonce = generate_nonce()
    used_nonces = {nonce: int(time.time())}
    valid, reason = is_nonce_valid(nonce, used_nonces)
    assert not valid
    assert "replay" in reason.lower()
    print("[PASS] test_nonce_replay (Replay detectado)")


def test_nonce_expirado():
    # Un nonce con timestamp fuera de la ventana temporal debe rechazarse.
    nonce_viejo = f"abc123-{int(time.time()) - 600}"
    valid, _ = is_nonce_valid(nonce_viejo, {})
    assert not valid
    print("[PASS] test_nonce_expirado")


def test_nonce_valido():
    # Un nonce nuevo dentro de la ventana temporal debe aceptarse.
    valid, reason = is_nonce_valid(generate_nonce(), {})
    assert valid, reason
    print("[PASS] test_nonce_valido")


# --- Credenciales (PBKDF2 + salt, contra Key derivation y BruteForce) ---

def test_password_correcta():
    # Una contrasena correcta debe verificarse contra su hash almacenado.
    pw_hash, salt = hash_password("miPassword123!")
    assert verify_password("miPassword123!", pw_hash, salt)
    print("[PASS] test_password_correcta")


def test_password_incorrecta():
    # Una contrasena incorrecta debe fallar la verificacion.
    pw_hash, salt = hash_password("correcta")
    assert not verify_password("incorrecta", pw_hash, salt)
    print("[PASS] test_password_incorrecta")


def test_salt_unico_por_usuario():
    # Cada hash debe tener un salt distinto (evita tablas rainbow).
    _, salt1 = hash_password("misma_password")
    _, salt2 = hash_password("misma_password")
    assert salt1 != salt2
    print("[PASS] test_salt_unico_por_usuario")


# --- Empaquetado de mensajes (payload || MAC || NONCE) ---

def test_pack_unpack_consistente():
    # El empaquetado y desempaquetado deben ser consistentes y el MAC verificable.
    payload = "TRANSACTION|ES111|ES222|500.00"
    packed = pack_message(payload, MASTER_KEY)
    unpacked = unpack_message(packed)
    assert unpacked is not None
    p, mac, nonce = unpacked
    assert p == payload
    assert verify_mac(p, nonce, mac, MASTER_KEY)
    print("[PASS] test_pack_unpack_consistente")


def test_unpack_formato_invalido():
    # Un mensaje con formato incorrecto debe devolver None.
    assert unpack_message("mensajesinformat") is None
    assert unpack_message("") is None
    print("[PASS] test_unpack_formato_invalido")


# --- Secure Comparator (contra Lateral Channel) ---

def test_secure_comparator_mac():
    # verify_mac usa compare_digest: MACs distintos deben fallar sin importar donde difieren.
    nonce = generate_nonce()
    mac_real = generate_mac("mensaje", nonce, MASTER_KEY)
    mac_falso = "a" * len(mac_real)
    assert not verify_mac("mensaje", nonce, mac_falso, MASTER_KEY)
    print("[PASS] test_secure_comparator_mac")


# --- Ejecucion ---

if __name__ == "__main__":
    print("=" * 50)
    print("  TESTS DE SEGURIDAD - INTEGRIDOS")
    print("=" * 50)
    print()

    tests = [
        test_mac_valido,
        test_mac_mensaje_alterado,
        test_mac_clave_incorrecta,
        test_nonce_replay,
        test_nonce_expirado,
        test_nonce_valido,
        test_password_correcta,
        test_password_incorrecta,
        test_salt_unico_por_usuario,
        test_pack_unpack_consistente,
        test_unpack_formato_invalido,
        test_secure_comparator_mac,
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
    print("Todos los tests OK!" if failed == 0 else f"{failed} tests fallaron")
