"""
Taller 2 - Parte 3 - RC4 sobre un diccionario personalizado de 64 símbolos (6 bits)

En vez de trabajar con bytes (0-255, 8 bits) como el RC4 clásico, aquí el
alfabeto de trabajo es el diccionario D de 64 caracteres indicado en el
taller, así que cada símbolo se representa con 6 bits (0-63) y el KSA/PRGA
de RC4 se ejecutan módulo 64 en vez de módulo 256.
"""

DICCIONARIO = ("ABCDEFGHIJKLMNÑOPQRSTUVWXYZÁÉÍÓÚ"
               "abcdefghijklmnñopqrstuvwxyzáéíóú")

assert len(DICCIONARIO) == 64, f"El diccionario tiene {len(DICCIONARIO)} símbolos, se esperaban 64"

CHAR_TO_IDX = {c: i for i, c in enumerate(DICCIONARIO)}
IDX_TO_CHAR = {i: c for i, c in enumerate(DICCIONARIO)}

N = 64  # tamaño del alfabeto -> 6 bits por símbolo


def texto_a_indices(texto: str):
    try:
        return [CHAR_TO_IDX[c] for c in texto]
    except KeyError as e:
        raise ValueError(f"El carácter {e} no está en el diccionario de 64 símbolos") from e


def indices_a_texto(indices):
    return "".join(IDX_TO_CHAR[i] for i in indices)


def ksa(key_indices):
    """Key-Scheduling Algorithm de RC4, adaptado a módulo N=64."""
    S = list(range(N))
    j = 0
    klen = len(key_indices)
    for i in range(N):
        j = (j + S[i] + key_indices[i % klen]) % N
        S[i], S[j] = S[j], S[i]
    return S


def prga(S, length):
    """Pseudo-Random Generation Algorithm de RC4, adaptado a módulo N=64.
    Devuelve una lista de 'length' índices (0-63) que forman el keystream."""
    S = S.copy()
    i = j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % N
        j = (j + S[i]) % N
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % N]
        keystream.append(k)
    return keystream


def rc4_generar_keystream(clave: str, longitud: int):
    if not (4 <= len(clave) <= 32):
        raise ValueError("La clave debe tener entre 4 y 32 caracteres del diccionario")
    key_idx = texto_a_indices(clave)
    S = ksa(key_idx)
    return prga(S, longitud)


def rc4_cifrar(clave: str, mensaje: str):
    msg_idx = texto_a_indices(mensaje)
    keystream = rc4_generar_keystream(clave, len(msg_idx))
    cifrado_idx = [m ^ k for m, k in zip(msg_idx, keystream)]
    return cifrado_idx, keystream, msg_idx


def rc4_descifrar(clave: str, cifrado_idx):
    keystream = rc4_generar_keystream(clave, len(cifrado_idx))
    plano_idx = [c ^ k for c, k in zip(cifrado_idx, keystream)]
    return indices_a_texto(plano_idx)


def a_binario_6bits(indices):
    return " ".join(f"{v:06b}" for v in indices)


if __name__ == "__main__":
    MENSAJE = "MensajeDePruebaDeCifradoDeFlujoParaCriptología"
    CLAVE = "ClaveSegura"

    print("Diccionario (64 símbolos):")
    print(" ", DICCIONARIO)
    print()

    cifrado_idx, keystream, msg_idx = rc4_cifrar(CLAVE, MENSAJE)
    cifrado_txt = indices_a_texto(cifrado_idx)

    print("=== Ejercicio 2 (Parte 3): cifrado con clave 'ClaveSegura' ===")
    print("Mensaje              :", MENSAJE)
    print("Mensaje en binario (6 bits/carácter):")
    print(" ", a_binario_6bits(msg_idx))
    print()
    print("KeyStream en binario (6 bits/carácter):")
    print(" ", a_binario_6bits(keystream))
    print()
    print("XOR (mensaje ^ keystream) en binario:")
    print(" ", a_binario_6bits(cifrado_idx))
    print()
    print("Mensaje cifrado (en el diccionario):", cifrado_txt)
    print()

    # Verificación de descifrado con la clave correcta
    recuperado = rc4_descifrar(CLAVE, cifrado_idx)
    print("Descifrado con la clave correcta:", recuperado)
    print("¿Coincide con el mensaje original?", recuperado == MENSAJE)
    print()

    print("=== Ejercicio 3 (Parte 3): cifrado con clave propia ===")
    CLAVE_PROPIA = "CriptologiaSegura"  # cámbienla por la que escojan (4-32 letras del diccionario, sin números)
    cifrado_idx2, keystream2, _ = rc4_cifrar(CLAVE_PROPIA, MENSAJE)
    cifrado_txt2 = indices_a_texto(cifrado_idx2)
    print("Clave propia          :", CLAVE_PROPIA)
    print("Mensaje cifrado       :", cifrado_txt2)

    # a) Descifrar con la clave correcta
    print("Descifrado (clave correcta)  :", rc4_descifrar(CLAVE_PROPIA, cifrado_idx2))

    # b) Descifrar cambiando un carácter de la clave
    clave_incorrecta = "XriptologiaSegura"  # se cambió la primera letra
    print("Descifrado (clave incorrecta):", rc4_descifrar(clave_incorrecta, cifrado_idx2))
