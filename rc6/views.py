from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework.decorators import api_view

from .serializers import RC6CipherSerializer
from rc6_simetric import rc6_encrypt, rc6_decrypt

from rsa_crypto import generate_rsa_keys, rsa_encrypt, rsa_decrypt


import hashlib
import base64

# Generar las claves RSA
private_key_pem, public_key_pem = generate_rsa_keys()

@api_view(['POST'])
def cifrar_datos(request):
    # Serializar y validar los datos de entrada
    serializer = RC6CipherSerializer(data=request.data)

    if serializer.is_valid():
        # Obtener los datos validados
        key = serializer.validated_data['key'].encode('utf-8')
        name = serializer.validated_data['name'].encode('utf-8')
        email = serializer.validated_data['email'].encode('utf-8')
        address = serializer.validated_data['address'].encode('utf-8')
        phone = serializer.validated_data['phone'].encode('utf-8')
        credit_card = serializer.validated_data['credit_card'].encode('utf-8')
        password = serializer.validated_data['password'].encode('utf-8')

        # Cifrar con RC6
        encrypted_name = base64.b64encode(rc6_encrypt(key, name)).decode('utf-8')
        encrypted_email = base64.b64encode(rc6_encrypt(key, email)).decode('utf-8')
        encrypted_address = base64.b64encode(rc6_encrypt(key, address)).decode('utf-8')

        # Cifrar con RSA los campos 'phone' y 'credit_card'
        encrypted_phone = base64.b64encode(rsa_encrypt(public_key_pem, phone.decode('utf-8'))).decode('utf-8')
        encrypted_credit_card = base64.b64encode(rsa_encrypt(public_key_pem, credit_card.decode('utf-8'))).decode('utf-8')

        # Cifrar con HASH (BLAKE2) 
        encrypted_password = hashlib.blake2b(password).hexdigest()

        # Devolver los datos cifrados en la respuesta JSON
        return Response({
            'encrypted_name': encrypted_name,
            'encrypted_email': encrypted_email,
            'encrypted_address': encrypted_address,
            'encrypted_password': encrypted_password,
            'encrypted_phone': encrypted_phone,
            'encrypted_credit_card': encrypted_credit_card,
        })
    else:
        return Response(serializer.errors, status=400)
    
@api_view(['POST'])
def descifrar_datos(request):
    # Obtener la clave de descifrado y la clave utilizada en el cifrado original
    key_decrypt = request.data.get('key_decrypt')
    key_used = request.data.get('key_used')

    if key_decrypt and key_used and key_decrypt == key_used:
        # Obtener los datos cifrados
        encrypted_name = request.data.get('encrypted_name')
        encrypted_email = request.data.get('encrypted_email')
        encrypted_phone = request.data.get('encrypted_phone')
        encrypted_address = request.data.get('encrypted_address')
        encrypted_credit_card = request.data.get('encrypted_credit_card')

        # Verificar si los datos están presentes
        if not (encrypted_name and encrypted_email and encrypted_phone and encrypted_address and encrypted_credit_card):
            return Response({"error": "Datos cifrados incompletos"}, status=400)

        try:
            # Convertir la clave de descifrado a bytes
            key_decrypt_bytes = key_decrypt.encode('utf-8')

            # Descifrar los datos con RC6
            decrypted_name = rc6_decrypt(key_decrypt_bytes, base64.b64decode(encrypted_name)).decode('utf-8')
            decrypted_email = rc6_decrypt(key_decrypt_bytes, base64.b64decode(encrypted_email)).decode('utf-8')
            decrypted_address = rc6_decrypt(key_decrypt_bytes, base64.b64decode(encrypted_address)).decode('utf-8')

            # Descifrar los datos con RSA
            decrypted_phone = rsa_decrypt(private_key_pem, base64.b64decode(encrypted_phone))
            decrypted_credit_card = rsa_decrypt(private_key_pem, base64.b64decode(encrypted_credit_card))

            # Devolver los datos descifrados
            return Response({
                'decrypted_name': decrypted_name,
                'decrypted_email': decrypted_email,
                'decrypted_phone': decrypted_phone,
                'decrypted_address': decrypted_address,
                'decrypted_credit_card': decrypted_credit_card,
                'decrypted_password': 'Un cifrado HASH es imposible de descifrar'
            })
        except Exception as e:
            return Response({"error": f"Error al descifrar los datos: {str(e)}"}, status=400)
    else:
        return Response({"error": "La clave de descifrado no coincide con la clave original"}, status=400)

# CIFRADO RABIN

# ## Vista para cifrar usando Rabin
# @csrf_exempt

# @api_view(['POST'])
# def rabin_encrypt_view(request):
#     message = request.data.get('message')

#     if message is None:
#         return Response({"error": "El campo 'message' es requerido."}, status=400)

#     try:
#         # Convertir el mensaje a entero
#         m = int(message)

#         # Agregar marcador al mensaje original (ejemplo: agregar "999" al final)
#         marker = 999
#         message_with_marker = int(f"{m}{marker}")

#         # Generar claves
#         p, q = generar_primos()
#         n = p * q

#         # Cifrar el mensaje con marcador
#         c = exponenciacion_modular(message_with_marker, 2, n)

#         return Response({
#             'ciphertext': c,
#             'public_key_n': n,
#             'p': p,
#             'q': q,
#             'marker': marker  # Devuelve el marcador para referencia
#         })
#     except Exception as e:
#         return Response({"error": f"Error al cifrar el mensaje: {str(e)}"}, status=500)
    
# # Vista para descifrar usando Rabin
# @csrf_exempt
# @api_view(['POST'])
# def rabin_decrypt_view(request):
#     ciphertext = request.data.get('ciphertext')
#     p = request.data.get('p')
#     q = request.data.get('q')
#     marker = request.data.get('marker')

#     if ciphertext is None or p is None or q is None or marker is None:
#         return Response({"error": "Los campos 'ciphertext', 'p', 'q', y 'marker' son requeridos."}, status=400)

#     try:
#         # Convertir los valores recibidos a enteros
#         ciphertext = int(ciphertext)
#         p = int(p)
#         q = int(q)
#         marker = str(marker)

#         # Generar n
#         n = p * q

#         # Descifrar el mensaje (calcular las cuatro posibles raíces)
#         soluciones = calcular_raices(ciphertext, p, q)

#         # Validación: Buscar la solución que contiene el marcador
#         solucion_correcta = None
#         for solucion in soluciones:
#             if str(solucion).endswith(marker):  # Verificar si la solución contiene el marcador
#                 solucion_correcta = str(solucion)[:-len(marker)]  # Quitar el marcador para obtener el número original
#                 break

#         return Response({
#             'ciphertext': ciphertext,
#             'posibles_soluciones': soluciones,  # Soluciones en decimal
#             'solucion_correcta': solucion_correcta  # La solución correcta basada en el marcador
#         })
#     except Exception as e:
#         return Response({"error": f"Error al descifrar el mensaje: {str(e)}"}, status=500)
