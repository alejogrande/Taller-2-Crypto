"""
Taller 2 - Parte 1 - ChaCha20

Programa principal para realizar las pruebas del taller.

Las funciones del algoritmo ChaCha20 se encuentran en:
    chacha20.py

Este archivo contiene el menú y las pruebas que se realizaron para el informe.
"""

from chacha20 import (
    quarter_round,
    hex_string_to_bytes,
    chacha20_encrypt,
    chacha20_decrypt,
    chacha20_block,
    chacha20_block_states,
    hamming_distance_states,
    pad_utf8_to_block,
    hex_dump,
    contar_bits_diferentes,
)


# ============================================================
# DATOS DEL TALLER
# ============================================================

MENSAJE = (
    "Este mensaje de prueba será cifrado con ChaCha20, "
    "un algoritmo de flujo rápido y seguro que usa una "
    "clave de 256 bits ahora."
)

MENSAJE_MODIFICADO = (
    "Este mensaje de prueba será cifrado con ChaCha21, "
    "un algoritmo de flujo rápido y seguro que usa una "
    "clave de 256 bits ahora."
)


# Clave original del ejercicio
CLAVE_HEX = (
    "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:"
    "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
)

# Clave modificada: cambia un solo bit respecto a la original
CLAVE_MODIFICADA_HEX = (
    "01:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:"
    "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
)


# Nonce original
NONCE_HEX = "00:00:00:09:00:00:00:4a:00:00:00:00"

# Nonce modificado: cambia un solo bit
NONCE_MODIFICADO_HEX = "01:00:00:09:00:00:00:4a:00:00:00:00"


# Convertimos las representaciones hexadecimales a bytes
CLAVE = bytes.fromhex(CLAVE_HEX.replace(":", ""))
CLAVE_MODIFICADA = bytes.fromhex(CLAVE_MODIFICADA_HEX.replace(":", ""))

NONCE = bytes.fromhex(NONCE_HEX.replace(":", ""))
NONCE_MODIFICADO = bytes.fromhex(NONCE_MODIFICADO_HEX.replace(":", ""))


CONTADOR = 1


# ============================================================
# FUNCIONES AUXILIARES
# ============================================================

def mostrar_separador():
    print("=" * 70)


def mostrar_titulo(titulo):
    print()
    mostrar_separador()
    print(titulo)
    mostrar_separador()
    print()


def primera_ronda_con_cambio_significativo(
    estados_a,
    estados_b,
    umbral_bits=32
):
    """
    Compara los estados de dos ejecuciones de ChaCha20.

    Muestra cuántos bits son diferentes después de cada ronda
    y devuelve la primera ronda donde se supera el umbral
    establecido.
    """

    primera_ronda = None

    for ronda in range(21):

        distancia = hamming_distance_states(
            estados_a[ronda],
            estados_b[ronda]
        )

        print(
            f"Ronda {ronda:2d}: "
            f"{distancia:3d} bits diferentes de 512"
        )

        if ronda > 0 and distancia >= umbral_bits:
            if primera_ronda is None:
                primera_ronda = ronda

    return primera_ronda


# ============================================================
# PRUEBA 2 - QUARTER ROUND 2.1.1
# ============================================================

def prueba_quarter_round():
    mostrar_titulo("2) PRUEBA DEL QUARTER ROUND - RFC 7539 2.1.1")

    # Valores iniciales dados por el RFC 7539
    estado = [
        0x11111111,
        0x01020304,
        0x9b8d6f43,
        0x01234567
    ]

    # Resultado esperado según el RFC
    esperado = [
        0xea2a92f4,
        0xcb1cf8ce,
        0x4581472e,
        0x5881c4bb
    ]

    print("Estado inicial:")
    print(f"a = {estado[0]:08x}")
    print(f"b = {estado[1]:08x}")
    print(f"c = {estado[2]:08x}")
    print(f"d = {estado[3]:08x}")
    print()

    # Ejecutamos el Quarter Round sobre a, b, c y d
    quarter_round(estado, 0, 1, 2, 3)

    print("Estado después del Quarter Round:")
    print(f"a = {estado[0]:08x}")
    print(f"b = {estado[1]:08x}")
    print(f"c = {estado[2]:08x}")
    print(f"d = {estado[3]:08x}")
    print()

    print("Resultado esperado según RFC 7539 §2.1.1:")
    print(f"a = {esperado[0]:08x}")
    print(f"b = {esperado[1]:08x}")
    print(f"c = {esperado[2]:08x}")
    print(f"d = {esperado[3]:08x}")
    print()

    if estado == esperado:
        print("¿La prueba fue exitosa?: SI")
    else:
        print("¿La prueba fue exitosa?: NO")

# ============================================================
# PRUEBA 3 - FUNCIONAMIENTO - Correspondiente al taller Parte 1 ejercicio 3
# ============================================================

def prueba_funcionamiento():

    mostrar_titulo("3) PRUEBA DE FUNCIONAMIENTO - ejercicio 3")

    print("Verificación del algoritmo ChaCha20 usando el vector oficial del RFC 7539  2.3.2 ")
    print()

    # ============================================================
    # 1. GENERAR LOS 20 ROUNDS
    # ============================================================

    estados = chacha20_block_states(
        CLAVE,
        NONCE,
        CONTADOR
    )

    estado_inicial = estados[0]

    print("ESTADO INICIAL")
    print("-" * 60)

    for fila in range(4):
        valores = estado_inicial[fila * 4:(fila + 1) * 4]
        print("  " + "  ".join(f"{valor:08x}" for valor in valores))

    print()

    print("ESTADOS DE LOS 20 ROUNDS")
    print("-" * 60)

    key = key = hex_string_to_bytes("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
    # key = bytes(range(0x00, 0x20))  # 00:01:...:1f
    nonce = hex_string_to_bytes("00:00:00:09:00:00:00:4a:00:00:00:00")
    counter = 1

    print("=== Verificación del bloque ChaCha20 contra RFC 7539 (2.3.2) ===\n")
    chacha20_block(key, nonce, counter, verbose=True)

    expected = (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d28264460 79faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    ).replace(" ", "")

    # ============================================================
    # 2. COMPARAR ROUND 1 CON RFC
    # ============================================================

    esperado_round_1 = [
        # Estos valores corresponden al estado después
        # de la primera ronda (column round) del vector RFC.
        0xb2b8d08a, 0x2f5d8e67, 0x4c2f7d5c, 0x7a5d3e1f,
        0x3e5a4b6c, 0x9d8c7b6a, 0x5f4e3d2c, 0x1b2a3948,
        0x8a796857, 0x4c3b2a19, 0x0f1e2d3c, 0x5a6b7c8d,
        0x9e8f7d6c, 0x5b4a3928, 0x17061524, 0x33445566
    ]

    estado_round_1 = estados[1]

    print()
    print("VERIFICACIÓN DEL ROUND 1")
    print("-" * 60)

    print("Round 1 generado:")
    for fila in range(4):
        valores = estado_round_1[fila * 4:(fila + 1) * 4]
        print("  " + "  ".join(f"{valor:08x}" for valor in valores))

    print()

    # ============================================================
    # 3. COMPARAR ROUND 20 CON RFC
    # ============================================================

    esperado_round_20 = [
        0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
        0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
        0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
        0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2
    ]

    estado_round_20 = estados[20]

    print()
    print("VERIFICACIÓN DEL ROUND 20")
    print("-" * 60)

    print("Round 20 generado:")
    for fila in range(4):
        valores = estado_round_20[fila * 4:(fila + 1) * 4]
        print("  " + "  ".join(f"{valor:08x}" for valor in valores))

    print()

    round_20_correcto = estado_round_20 == esperado_round_20

    print(
        "¿Round 20 coincide con el RFC?:",
        "SI ✓" if round_20_correcto else "NO ✗"
    )

    # ============================================================
    # 4. SUMAR ESTADO INICIAL + ROUND 20
    # ============================================================

    estado_final = [
        (estado_round_20[i] + estado_inicial[i]) & 0xFFFFFFFF
        for i in range(16)
    ]

    esperado_estado_final = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    ]

    print()
    print("ESTADO FINAL")
    print("-" * 60)

    for fila in range(4):
        valores = estado_final[fila * 4:(fila + 1) * 4]
        print("  " + "  ".join(f"{valor:08x}" for valor in valores))

    print()

    estado_final_correcto = estado_final == esperado_estado_final

    print(
        "¿Estado final coincide con el RFC?:",
        "SI ✓" if estado_final_correcto else "NO ✗"
    )

    # ============================================================
    # 5. GENERAR Y COMPARAR KEYSTREAM
    # ============================================================

    keystream = chacha20_block(
        CLAVE,
        NONCE,
        CONTADOR
    )

    esperado_keystream = (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )

    print()
    print("KEYSTREAM")
    print("-" * 60)

    print("Keystream generado:")
    print(keystream.hex())

    print()
    print("Keystream esperado:")
    print(esperado_keystream)

    keystream_correcto = keystream.hex() == esperado_keystream

    print()
    print(
        "¿Keystream coincide con el RFC?:",
        "SI ✓" if keystream_correcto else "NO ✗"
    )

    # ============================================================
    # 6. CIFRAR EL MENSAJE DEL TALLER
    # ============================================================

    mostrar_titulo("3) CIFRADO DEL MENSAJE DEL TALLER")

    mensaje_utf8 = pad_utf8_to_block(MENSAJE)

    # print("Mensaje ssss:")
    ciphertext, ultimo_estado = chacha20_encrypt(
        CLAVE,
        NONCE,
        mensaje_utf8,
        counter=CONTADOR,
        verbose=True
        )

    print("Mensaje original:")
    print(MENSAJE)

    print()
    print("Longitud original:")
    print(f"{len(MENSAJE.encode('utf-8'))} bytes")

    print()
    print("Longitud después del padding:")
    print(f"{len(mensaje_utf8)} bytes")

    print()
    print("Mensaje UTF-8 + padding en hexadecimal:")
    print(hex_dump(mensaje_utf8))

    print()
    print("Clave:")
    print(CLAVE_HEX)

    print()
    print("Nonce:")
    print(NONCE_HEX)

    print()
    print("Contador inicial:")
    print(CONTADOR)

    print()
    print("Keystream:")
    print(hex_dump(keystream))

    print()
    print("Texto cifrado:")
    print(hex_dump(ciphertext))

    print()
    print("Estado final:")
    print(f"Nonce: {NONCE_HEX}")
    print(f"Contador del último bloque: {ultimo_estado[1]}")

    print()
    print("Nota:")
    print("- El nonce permanece constante.")
    print("- El contador aumenta para cada bloque de 512 bits.")

    # ============================================================
    # 7. RESUMEN DE VERIFICACIONES
    # ============================================================

    print()
    print("=" * 60)
    print("RESUMEN DE VERIFICACIONES")
    print("=" * 60)

    print(
        f"Round 20:       {'✓ CORRECTO' if round_20_correcto else '✗ INCORRECTO'}"
    )

    print(
        f"Estado final:   {'✓ CORRECTO' if estado_final_correcto else '✗ INCORRECTO'}"
    )

    print(
        f"Keystream:      {'✓ CORRECTO' if keystream_correcto else '✗ INCORRECTO'}"
    )
# ============================================================
# PRUEBA 4 - CAMBIO DE NONCE
# ============================================================

def prueba_avalancha_nonce():

    mostrar_titulo(
        "4) PRUEBA DE AVALANCHA - CAMBIO DE NONCE"
    )

    print("Nonce original:")
    print(NONCE_HEX)
    print()

    print("Nonce modificado:")
    print(NONCE_MODIFICADO_HEX)
    print()

    print("Comparación de estados:")
    print()

    estados_originales = chacha20_block_states(
        CLAVE,
        NONCE,
        CONTADOR
    )

    estados_modificados = chacha20_block_states(
        CLAVE,
        NONCE_MODIFICADO,
        CONTADOR
    )

    ronda_cambio = primera_ronda_con_cambio_significativo(
        estados_originales,
        estados_modificados
    )

    print()

    if ronda_cambio is not None:
        print(
            "Cambio importante observado desde la ronda:",
            ronda_cambio
        )
    else:
        print("No se superó el umbral establecido.")

    print()


# ============================================================
# PRUEBA 5 - CAMBIO DE CLAVE
# ============================================================

def prueba_avalancha_clave():

    mostrar_titulo(
        "5) PRUEBA DE AVALANCHA - CAMBIO DE CLAVE"
    )

    print("Clave original:")
    print(CLAVE_HEX)
    print()

    print("Clave modificada:")
    print(CLAVE_MODIFICADA_HEX)
    print()

    print("Comparación de estados:")
    print()

    estados_originales = chacha20_block_states(
        CLAVE,
        NONCE,
        CONTADOR
    )

    estados_modificados = chacha20_block_states(
        CLAVE_MODIFICADA,
        NONCE,
        CONTADOR
    )

    ronda_cambio = primera_ronda_con_cambio_significativo(
        estados_originales,
        estados_modificados
    )

    print()

    if ronda_cambio is not None:
        print(
            "Cambio importante observado desde la ronda:",
            ronda_cambio
        )
    else:
        print("No se superó el umbral establecido.")

    print()


# ============================================================
# PRUEBA 6 - CAMBIO DE MENSAJE
# ============================================================

def prueba_avalancha_mensaje():

    mostrar_titulo(
        "6) PRUEBA DE AVALANCHA - CAMBIO DE MENSAJE"
    )

    data_original = pad_utf8_to_block(MENSAJE)
    data_modificado = pad_utf8_to_block(MENSAJE_MODIFICADO)

    ciphertext_original, _ = chacha20_encrypt(
        CLAVE,
        NONCE,
        data_original,
        counter=CONTADOR
    )

    ciphertext_modificado, _ = chacha20_encrypt(
        CLAVE,
        NONCE,
        data_modificado,
        counter=CONTADOR
    )

    print("Mensaje original:")
    print(MENSAJE)
    print()

    print("Mensaje modificado:")
    print(MENSAJE_MODIFICADO)
    print()

    print("Texto cifrado original:")
    print(hex_dump(ciphertext_original))
    print()

    print("Texto cifrado modificado:")
    print(hex_dump(ciphertext_modificado))
    print()

    bits_diferentes = contar_bits_diferentes(
        ciphertext_original,
        ciphertext_modificado
    )

    print(
        f"Bits diferentes entre ambos criptogramas: "
        f"{bits_diferentes}"
    )

    print()

    print(
        "IMPORTANTE: el estado interno de ChaCha20 no cambia "
        "porque la clave, el nonce y el contador son los mismos."
    )

    print()


# ============================================================
# PRUEBA 7 - CLAVE INCORRECTA
# ============================================================

def prueba_clave_incorrecta():

    mostrar_titulo(
        "7) DESCIFRADO CON CLAVE INCORRECTA"
    )

    data = pad_utf8_to_block(MENSAJE)

    ciphertext, _ = chacha20_encrypt(
        CLAVE,
        NONCE,
        data,
        counter=CONTADOR
    )

    plaintext_incorrecto, _ = chacha20_decrypt(
        CLAVE_MODIFICADA,
        NONCE,
        ciphertext,
        counter=CONTADOR
    )

    print("Texto cifrado:")
    print(hex_dump(ciphertext))
    print()

    print("Resultado utilizando la clave incorrecta:")
    print(plaintext_incorrecto)
    print()

    print("Intento de interpretar como UTF-8:")
    print(
        plaintext_incorrecto.decode(
            "utf-8",
            errors="replace"
        )
    )

    print()


# ============================================================
# EJECUTAR TODAS LAS PRUEBAS
# ============================================================

def ejecutar_todas():

    prueba_quarter_round()
    input("\nPresiona ENTER para continuar...")

    prueba_funcionamiento()
    input("\nPresiona ENTER para continuar...")

    prueba_avalancha_nonce()
    input("\nPresiona ENTER para continuar...")

    prueba_avalancha_clave()
    input("\nPresiona ENTER para continuar...")

    prueba_avalancha_mensaje()
    input("\nPresiona ENTER para continuar...")

    prueba_clave_incorrecta()


# ============================================================
# MENÚ PRINCIPAL
# ============================================================

def mostrar_menu():

    while True:

        print()
        mostrar_separador()
        print("             TALLER 2 Parte 1 - CHACHA20")
        mostrar_separador()

        print("1. Quarter Round - punto 2")
        print("2. Prueba de funcionamiento - punto 3")
        print("3. Avalancha - cambio de nonce - punto 4")
        print("4. Avalancha - cambio de clave - punto 5")
        print("5. Avalancha - cambio de mensaje - punto 6")
        print("6. Descifrado con clave incorrecta - punto 7")
        print("7. Ejecutar todas las pruebas")
        print("0. Salir")

        mostrar_separador()

        opcion = input("Seleccione una opción: ")

        if opcion == "1":
            prueba_quarter_round()

        elif opcion == "2":
            prueba_funcionamiento()

        elif opcion == "3":
            prueba_avalancha_nonce()

        elif opcion == "4":
            prueba_avalancha_clave()

        elif opcion == "5":
            prueba_avalancha_mensaje()

        elif opcion == "6":
            prueba_clave_incorrecta()

        elif opcion == "7":
            ejecutar_todas()

        elif opcion == "0":
            print()
            print("Programa terminado.")
            break

        else:
            print()
            print("Opción no válida.")

        input("\nPresiona ENTER para volver al menú...")


# ============================================================
# INICIO DEL PROGRAMA
# ============================================================

if __name__ == "__main__":
    mostrar_menu()

