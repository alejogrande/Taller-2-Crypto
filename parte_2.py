"""
Taller 2 - Parte 2 - Cifrador CSS (Content Scrambling System)
Implementación educativa basada en dos LFSR (17 bits y 25 bits)

IMPORTANTE: Esta es una reconstrucción didáctica de CSS a partir de la
descripción clásica (dos LFSR combinados con suma módulo 256 y acarreo).
CSS es un algoritmo histórico (años 80-90) ya criptoanalizado y roto desde
1999; no protege contenido real en la actualidad y se usa aquí únicamente
con fines académicos, tal como lo pide el taller. Si el material de
clase define una convención distinta de bits (por ejemplo, orden de los
bits al ensamblar el byte, o dirección del corrimiento), ajusten las
funciones marcadas con "AJUSTAR SI ES NECESARIO" para que coincida
exactamente con el diagrama visto en clase.
"""


class LFSR:
    """LFSR tipo Fibonacci.
    bits: lista de 0/1, donde bits[0] es el bit menos significativo (LSB).
    taps: posiciones (desde el LSB) que participan en la realimentación.
    """

    def __init__(self, seed_value: int, n_bits: int, taps):
        if seed_value == 0:
            raise ValueError("La semilla del LFSR no puede ser todo ceros")
        self.n = n_bits
        self.taps = taps
        self.bits = [(seed_value >> i) & 1 for i in range(n_bits)]

    def clock(self):
        """Realiza un ciclo de reloj: calcula el bit de realimentación,
        desplaza el registro y devuelve el bit de salida (el que sale)."""
        feedback = 0
        for t in self.taps:
            feedback ^= self.bits[t]
        salida = self.bits[0]                 # AJUSTAR SI ES NECESARIO
        self.bits = self.bits[1:] + [feedback]  # corrimiento a la derecha
        return salida

    def clock_byte(self):
        """Genera un byte clocando el registro 8 veces (primer bit -> MSB)."""
        byte = 0
        for _ in range(8):
            b = self.clock()
            byte = (byte << 1) | b            # AJUSTAR SI ES NECESARIO
        return byte & 0xFF


def preparar_registros(key40: bytes):
    """Recibe la semilla (clave) de 40 bits (5 bytes) y devuelve los dos
    LFSR ya inicializados según la especificación del taller:
      - S1: registro de 17 bits, taps {14, 0}, alimentado con 1 + los
        16 bits más significativos de la clave.
      - S2: registro de 25 bits, taps {12, 4, 3, 0}, alimentado con 1 +
        los 24 bits menos significativos de la clave.
    """
    if len(key40) != 5:
        raise ValueError("La clave CSS debe tener 40 bits (5 bytes)")

    key_int = int.from_bytes(key40, "big")
    top16 = (key_int >> 24) & 0xFFFF      # 16 bits más significativos
    bottom24 = key_int & 0xFFFFFF         # 24 bits menos significativos

    seed_s1 = (1 << 16) | top16           # fija un 1 en el bit más significativo
    seed_s2 = (1 << 24) | bottom24        # fija un 1 en el bit más significativo

    s1 = LFSR(seed_s1, 17, taps=[14, 0])
    s2 = LFSR(seed_s2, 25, taps=[12, 4, 3, 0])
    return s1, s2


def css_keystream(key40: bytes, n_bytes: int):
    """Genera 'n_bytes' de keystream siguiendo los pasos 4 a 8 del taller:
       4) fija el acarreo c = 0
       5) clockea ambos registros 8 bits para obtener x_i, y_i (mod 256)
       6) realiza la suma (x_i + y_i + c) mod 256
       7) actualiza el acarreo: c = 1 si hubo desbordamiento, si no c = 0
       8) se repite por cada byte necesario
    """
    s1, s2 = preparar_registros(key40)
    carry = 0
    keystream = bytearray()
    for _ in range(n_bytes):
        x_i = s1.clock_byte()
        y_i = s2.clock_byte()
        suma = x_i + y_i + carry
        out_byte = suma & 0xFF
        carry = 1 if suma >= 256 else 0
        keystream.append(out_byte)
    return bytes(keystream)


def css_cifrar(key40: bytes, mensaje: bytes):
    ks = css_keystream(key40, len(mensaje))
    return bytes(m ^ k for m, k in zip(mensaje, ks))


def css_descifrar(key40: bytes, criptograma: bytes):
    # CSS, como todo cifrado de flujo por XOR, es simétrico
    return css_cifrar(key40, criptograma)


def contar_bits_diferentes(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    return sum(bin(x ^ y).count("1") for x, y in zip(a[:n], b[:n]))


if __name__ == "__main__":
    clave = bytes.fromhex("1A2B3C4D5E")  # 40 bits
    mensaje = ("El algoritmo CSS fue diseñado para proteger el contenido de los DVD "
               "mediante un cifrado de flujo basado en registros de desplazamiento. "
               "Aunque su seguridad fue superada, sigue siendo un hito clave en la "
               "historia de la gestión de los derechos digitales.").encode("utf-8")

    print("=== Ejercicio 1 (Parte 2): cifrado CSS del mensaje de prueba ===")
    ct = css_cifrar(clave, mensaje)
    print("Clave (hex)      :", clave.hex())
    print("Mensaje (utf-8)  :", mensaje)
    print("Criptograma (hex):", ct.hex())

    pt = css_descifrar(clave, ct)
    print("Descifrado OK?   :", pt == mensaje)
    print()

    print("=== Ejercicio 2 (Parte 2): prueba de avalancha ===")
    # Cambiar 1 bit de la clave
    clave_mod = bytes([clave[0] ^ 0x01]) + clave[1:]
    ct_clave_mod = css_cifrar(clave_mod, mensaje)
    bits_clave = contar_bits_diferentes(ct, ct_clave_mod)
    print(f"Bits diferentes al cambiar 1 bit de la clave  : {bits_clave} de {len(ct)*8}")

    # Cambiar 1 bit del mensaje
    mensaje_mod = bytearray(mensaje)
    mensaje_mod[0] ^= 0x01
    ct_msg_mod = css_cifrar(clave, bytes(mensaje_mod))
    bits_msg = contar_bits_diferentes(ct, ct_msg_mod)
    print(f"Bits diferentes al cambiar 1 bit del mensaje : {bits_msg} de {len(ct)*8}")
