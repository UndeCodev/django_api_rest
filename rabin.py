import random
from sympy import isprime

# Función para verificar si un número es primo
def es_primo(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Generar números primos p y q en un rango más grande
def generar_primos():
    while True:
        # Generamos números primos en el rango de millones para que n sea lo suficientemente grande
        p = random.randint(10**7, 10**9)
        q = random.randint(10**7, 10**9)

        # Verificamos que p y q sean primos, distintos y cumplan la condición (p - 3) % 4 == 0
        if isprime(p) and isprime(q) and p != q and (p - 3) % 4 == 0 and (q - 3) % 4 == 0:
            return p, q

# Exponenciación modular (m^e % n)
def exponenciacion_modular(base, exponente, mod):
    return pow(base, exponente, mod)

# Calcular las raíces modulares
def calcular_raices(c, p, q):
    # Calcular las raíces cuadradas modulares de c mod p y c mod q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    
    # Teorema chino del resto para combinar las soluciones
    def teorema_chino(mp, mq, p, q):
        q_inv_p = pow(q, -1, p)  # Inverso de q mod p
        p_inv_q = pow(p, -1, q)  # Inverso de p mod q
        n = p * q

        # Resolver las congruencias
        x1 = (mp * q * q_inv_p + mq * p * p_inv_q) % n
        x2 = (mp * q * q_inv_p - mq * p * p_inv_q) % n
        x3 = (-mp * q * q_inv_p + mq * p * p_inv_q) % n
        x4 = (-mp * q * q_inv_p - mq * p * p_inv_q) % n

        return [x1, x2, x3, x4]
    
    # Llamada a la función del teorema chino del resto
    return teorema_chino(mp, mq, p, q)