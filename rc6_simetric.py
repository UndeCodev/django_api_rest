import struct

# Parámetros del RC6
W = 32  # Número de bits por palabra (32 bits)
R = 20  # Número de rondas
LOG_W = 5  # log2(W)
P32 = 0xb7e15163  # Constante derivada de e
Q32 = 0x9e3779b9  # Constante derivada de phi

def rotate_left(x, y, w=W):
    """Rotación a la izquierda (Left Circular Rotation)."""
    return ((x << y) & (2 ** w - 1)) | (x >> (w - y))

def rotate_right(x, y, w=W):
    """Rotación a la derecha (Right Circular Rotation)."""
    return (x >> y) | ((x << (w - y)) & (2 ** w - 1))

def key_expansion(K):
    """Expansión de la clave."""
    L = []
    c = len(K) // 4
    for i in range(c):
        L.append(int.from_bytes(K[4 * i: 4 * (i + 1)], byteorder='little'))

    S = [(P32 + i * Q32) % (2 ** W) for i in range(2 * R + 4)]

    A = B = i = j = 0
    v = 3 * max(c, 2 * R + 4)
    for _ in range(v):
        A = S[i] = rotate_left((S[i] + A + B) % (2 ** W), 3)
        B = L[j] = rotate_left((L[j] + A + B) % (2 ** W), (A + B) % W)
        i = (i + 1) % len(S)
        j = (j + 1) % len(L)
    
    return S

def encrypt_block(plaintext, S):
    """Cifrado de un bloque de 128 bits."""
    A, B, C, D = struct.unpack('<4I', plaintext)

    B = (B + S[0]) % (2 ** W)
    D = (D + S[1]) % (2 ** W)

    for i in range(1, R + 1):
        t = rotate_left((B * (2 * B + 1)) % (2 ** W), LOG_W)
        u = rotate_left((D * (2 * D + 1)) % (2 ** W), LOG_W)
        A = (rotate_left(A ^ t, u % W) + S[2 * i]) % (2 ** W)
        C = (rotate_left(C ^ u, t % W) + S[2 * i + 1]) % (2 ** W)
        A, B, C, D = B, C, D, A

    A = (A + S[2 * R + 2]) % (2 ** W)
    C = (C + S[2 * R + 3]) % (2 ** W)

    return struct.pack('<4I', A, B, C, D)

def decrypt_block(ciphertext, S):
    """Descifrado de un bloque de 128 bits."""
    A, B, C, D = struct.unpack('<4I', ciphertext)

    C = (C - S[2 * R + 3]) % (2 ** W)
    A = (A - S[2 * R + 2]) % (2 ** W)

    for i in range(R, 0, -1):
        A, B, C, D = D, A, B, C
        u = rotate_left((D * (2 * D + 1)) % (2 ** W), LOG_W)
        t = rotate_left((B * (2 * B + 1)) % (2 ** W), LOG_W)
        C = (rotate_right((C - S[2 * i + 1]) % (2 ** W), t % W) ^ u)
        A = (rotate_right((A - S[2 * i]) % (2 ** W), u % W) ^ t)

    D = (D - S[1]) % (2 ** W)
    B = (B - S[0]) % (2 ** W)

    return struct.pack('<4I', A, B, C, D)

def rc6_encrypt(key, plaintext):
    """Función principal para cifrar con RC6."""
    # Expansión de la clave
    S = key_expansion(key)

    # Dividir el texto plano en bloques de 128 bits
    ciphertext = b''
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        if len(block) < 16:
            block = block.ljust(16, b'\0')
        ciphertext += encrypt_block(block, S)
    
    return ciphertext

def rc6_decrypt(key, ciphertext):
    """Función principal para descifrar con RC6."""
    # Expansión de la clave
    S = key_expansion(key)

    # Dividir el texto cifrado en bloques de 128 bits
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext += decrypt_block(block, S)
    
    return plaintext.rstrip(b'\0')  # Eliminar padding
