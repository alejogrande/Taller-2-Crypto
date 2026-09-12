"""
ChaCha20 - Implementación para el Taller 2 (Criptología de flujo)
Basado en RFC 7539 (https://datatracker.ietf.org/doc/html/rfc7539)

Incluye:
 - Función de cuarto de ronda (Quarter Round)
 - Función de bloque ChaCha20 con impresión de la matriz hexadecimal
   en cada una de las 20 rondas (formato RFC 7539 sección 2.2/2.3)
 - Cifrado / descifrado de mensajes (XOR con el keystream)
 - Utilidades para pruebas de avalancha (comparar bits entre dos salidas)
"""

import struct

MASK32 = 0xFFFFFFFF


def rotl32(x, n):
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def quarter_round(state, a, b, c, d):
    """Aplica un quarter round in-place sobre la lista 'state' (16 uint32)."""
    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & MASK32
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & MASK32
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def print_matrix(state, titulo=""):
    """Imprime el estado (16 palabras de 32 bits) como matriz 4x4 hexadecimal,
    igual al formato usado en la RFC 7539 sección 2.2 / 2.3."""
    if titulo:
        print(titulo)
    for row in range(4):
        vals = state[row * 4:(row + 1) * 4]
        print("  " + "  ".join(f"{v:08x}" for v in vals))
    print()


def build_initial_state(key: bytes, nonce: bytes, counter: int):
    """Construye el estado inicial de 16 palabras de 32 bits:
       - 4 constantes ("expand 32-byte k")
       - 8 palabras de la clave (32 bytes)
       - 1 palabra de contador
       - 3 palabras de nonce (12 bytes)
    """
    assert len(key) == 32, "La clave debe ser de 32 bytes (256 bits)"
    assert len(nonce) == 12, "El nonce debe ser de 12 bytes (96 bits)"

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<3I", nonce))

    state = constants + key_words + [counter & MASK32] + nonce_words
    return state


def chacha20_block_states(key: bytes, nonce: bytes, counter: int):
    """Igual que chacha20_block, pero devuelve la lista de los 21 estados
    (estado inicial + estado después de cada una de las 20 rondas) para
    poder comparar bit a bit en las pruebas de avalancha."""
    state = build_initial_state(key, nonce, counter)
    working = state.copy()
    estados = [working.copy()]

    for i in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        estados.append(working.copy())

        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
        estados.append(working.copy())

    return estados  # longitud 21: índice 0 = inicial, índice i = tras ronda i


def hamming_distance_states(s1, s2):
    """Cuenta bits distintos entre dos estados (listas de 16 uint32)."""
    total = 0
    for a, b in zip(s1, s2):
        total += bin((a ^ b) & MASK32).count("1")
    return total


def chacha20_block(key: bytes, nonce: bytes, counter: int, verbose=False):
    """Genera un bloque de 64 bytes (keystream) y opcionalmente imprime
    la matriz hexadecimal después de cada ronda (20 rondas => 10 iteraciones
    de ronda impar + ronda par)."""
    state = build_initial_state(key, nonce, counter)
    working = state.copy()

    if verbose:
        print_matrix(working, "Estado inicial:")

    for i in range(10):  # 10 * 2 = 20 rondas
        # Ronda impar (columnas)
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        if verbose:
            print_matrix(working, f"Después de la ronda {2*i+1} (columnas):")

        # Ronda par (diagonales)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
        if verbose:
            print_matrix(working, f"Después de la ronda {2*i+2} (diagonales):")

    output = [(working[i] + state[i]) & MASK32 for i in range(16)]
    if verbose:
        print_matrix(output, "Estado final (suma con el estado inicial):")

    return struct.pack("<16I", *output)


def chacha20_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                      counter: int = 1, verbose=False):
    """Cifra 'plaintext' (bytes) usando ChaCha20. Devuelve (ciphertext, nonce_final)."""
    ciphertext = bytearray()
    n_blocks = (len(plaintext) + 63) // 64

    for j in range(n_blocks):
        block_counter = counter + j
        keystream = chacha20_block(key, nonce, block_counter, verbose=verbose)
        chunk = plaintext[j * 64:(j + 1) * 64]
        ciphertext.extend(b ^ k for b, k in zip(chunk, keystream))

    # El "nonce final" reportado es el nonce usado + el último contador alcanzado
    nonce_final = (nonce, counter + n_blocks - 1)
    return bytes(ciphertext), nonce_final


def chacha20_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                      counter: int = 1, verbose=False):
    """ChaCha20 es simétrico: descifrar = volver a aplicar el XOR con el keystream."""
    plaintext, nonce_final = chacha20_encrypt(key, nonce, ciphertext, counter, verbose)
    return plaintext, nonce_final


# ---------------------------------------------------------------------------
# Utilidades para el informe
# ---------------------------------------------------------------------------

def pad_utf8_to_block(mensaje: str, block_bytes: int = 64) -> bytes:
    """Codifica el mensaje en UTF-8 y lo rellena con ceros hasta un múltiplo
    de 512 bits (64 bytes), tal como pide el enunciado del taller."""
    data = mensaje.encode("utf-8")
    resto = len(data) % block_bytes
    if resto != 0:
        data += b"\x00" * (block_bytes - resto)
    return data


def hex_dump(data: bytes) -> str:
    return data.hex()


def contar_bits_diferentes(a: bytes, b: bytes) -> int:
    """Cuenta cuántos bits difieren entre dos secuencias de bytes de igual longitud
    (para las pruebas de efecto avalancha)."""
    n = min(len(a), len(b))
    total = 0
    for x, y in zip(a[:n], b[:n]):
        total += bin(x ^ y).count("1")
    return total


def flip_one_bit(data: bytes, byte_index: int = 0, bit_index: int = 0) -> bytes:
    """Devuelve una copia de 'data' con un solo bit invertido (para pruebas
    de avalancha sobre clave, nonce o mensaje)."""
    b = bytearray(data)
    b[byte_index] ^= (1 << bit_index)
    return bytes(b)

def hex_string_to_bytes(value):
    return bytes.fromhex(value.replace(":", ""))

# ---------------------------------------------------------------------------
# Verificación contra el vector de prueba de la RFC 7539, sección 2.3.2
# ---------------------------------------------------------------------------
