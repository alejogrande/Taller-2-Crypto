"""
Taller 2 - Parte 3 - Ataque de fuerza bruta contra el RC4 de 64 símbolos

IMPORTANTE SOBRE EL ALCANCE:
  El diccionario tiene 64 símbolos, así que el número de claves de 8
  caracteres es 64**8 = 2.81e14 (ver cálculo más abajo). Probar TODAS
  esas combinaciones en un computador normal no es realista para esta
  tarea (tomaría años). Por eso este script:
    1) Calcula y muestra, paso a paso, el tamaño real del espacio de
       claves de 8 caracteres (para responder la pregunta del informe).
    2) Ejecuta la fuerza bruta completa sobre un espacio DE DEMOSTRACIÓN
       reducido (clave más corta / alfabeto más pequeño) para que el
       ataque sí termine en segundos y puedan medir el tiempo real y
       ver la tabla de resultados, como pide el enunciado.
       Basta con cambiar LONGITUD_DEMO y/o ALFABETO_DEMO para repetir el
       experimento con otros tamaños y comparar tiempos.
"""

import itertools
import time

from rc4_custom import DICCIONARIO, rc4_descifrar, texto_a_indices, N

# ---------------------------------------------------------------------
# 1) Cálculo del tamaño del espacio de claves de 8 caracteres
# ---------------------------------------------------------------------
def calcular_espacio_claves(tam_alfabeto: int, longitud_clave: int):
    """Devuelve el número de claves posibles: tam_alfabeto ** longitud_clave,
    mostrando el cálculo paso a paso (como pide el enunciado)."""
    print(f"Tamaño del alfabeto (diccionario): {tam_alfabeto}")
    print(f"Longitud de la clave             : {longitud_clave}")
    total = 1
    for i in range(1, longitud_clave + 1):
        total *= tam_alfabeto
        print(f"  Después de la posición {i}: {tam_alfabeto}^{i} = {total:,}")
    print(f"Total de claves posibles = {tam_alfabeto}^{longitud_clave} = {total:,}")
    return total


# ---------------------------------------------------------------------
# 2) Fuerza bruta real, sobre un espacio reducido de demostración
# ---------------------------------------------------------------------
def es_texto_plausible(texto: str, vocales="aeiouáéíóú"):
    """Heurística simple para marcar resultados que 'parecen' texto en
    español: exige que TODOS los caracteres sean minúsculas 'normales'
    (sin tildes ni mayúsculas sueltas) y una proporción alta de vocales.
    Esto es solo un filtro de ejemplo: en un ataque real conviene comparar
    contra un diccionario de palabras válidas."""
    if not texto:
        return False
    if not all(c.islower() and c.isalpha() and c not in "ñáéíóú" for c in texto):
        return False
    vocales_en_texto = sum(1 for c in texto.lower() if c in vocales)
    return vocales_en_texto / len(texto) >= 0.35


def fuerza_bruta(mensaje_cifrado_idx, alfabeto_demo: str, longitud_clave: int,
                  max_resultados_interesantes=20):
    """Prueba TODAS las claves posibles de 'longitud_clave' caracteres
    tomadas de 'alfabeto_demo' y devuelve la tabla completa
    (clave -> mensaje descifrado) junto con el tiempo que tomó."""
    resultados = []
    interesantes = []

    inicio = time.time()
    total_probadas = 0
    for combinacion in itertools.product(alfabeto_demo, repeat=longitud_clave):
        clave = "".join(combinacion)
        texto = rc4_descifrar(clave, mensaje_cifrado_idx)
        resultados.append((clave, texto))
        total_probadas += 1
        if es_texto_plausible(texto):
            interesantes.append((clave, texto))
    duracion = time.time() - inicio

    print(f"\nSe probaron {total_probadas:,} claves en {duracion:.3f} segundos "
          f"({total_probadas/duracion:,.0f} claves/seg).")
    print(f"Candidatos que 'parecen' texto legible: {len(interesantes)}")
    for clave, texto in interesantes[:max_resultados_interesantes]:
        print(f"  clave={clave!r:15s} -> {texto}")

    return resultados, duracion


if __name__ == "__main__":
    print("################################################################")
    print("# Pregunta 1: tamaño del espacio de claves de 8 caracteres")
    print("################################################################")
    calcular_espacio_claves(tam_alfabeto=len(DICCIONARIO), longitud_clave=8)

    print()
    print("################################################################")
    print("# Demostración práctica de fuerza bruta (espacio reducido)")
    print("################################################################")

    # Mensaje de prueba (>= 10 caracteres, con sentido en español, sin espacios,
    # tal como exige el enunciado) cifrado con una clave CORTA y de un
    # alfabeto pequeño para que la búsqueda exhaustiva sea viable aquí mismo.
    from rc4_custom import rc4_cifrar

    MENSAJE_PRUEBA = "holamundoseguro"          # mensaje con sentido, sin espacios
    ALFABETO_DEMO = "abcdefghijklmnopqrstuvwxyz"  # sub-alfabeto de minúsculas (26 símbolos)
    LONGITUD_DEMO = 4                            # AJUSTAR: 4 ya da 26^4 = 456,976 claves

    CLAVE_SECRETA = "clav"  # clave real utilizada para cifrar (desconocida "para el atacante")
    cifrado_idx, _, _ = rc4_cifrar(CLAVE_SECRETA, MENSAJE_PRUEBA)

    print(f"Mensaje original : {MENSAJE_PRUEBA}")
    print(f"Clave secreta    : {CLAVE_SECRETA} (el 'atacante' no la conoce)")
    print(f"Alfabeto de claves de la demo: {ALFABETO_DEMO!r} ({len(ALFABETO_DEMO)} símbolos)")
    calcular_espacio_claves(tam_alfabeto=len(ALFABETO_DEMO), longitud_clave=LONGITUD_DEMO)

    tabla, duracion = fuerza_bruta(cifrado_idx, ALFABETO_DEMO, LONGITUD_DEMO)

    encontrada = [c for c, t in tabla if t == MENSAJE_PRUEBA]
    print(f"\n¿Se encontró la clave correcta en la búsqueda? {encontrada}")
