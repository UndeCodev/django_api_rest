from rest_framework import serializers

class RC6CipherSerializer(serializers.Serializer):
    key = serializers.CharField(max_length=16)
    name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    phone = serializers.CharField(max_length=15)
    address = serializers.CharField(max_length=255)
    credit_card = serializers.CharField(max_length=20)
    password = serializers.CharField(max_length=100)


class CifrarSerializer(serializers.Serializer):
    mensaje = serializers.IntegerField()

class DescifrarSerializer(serializers.Serializer):
    cifrado = serializers.IntegerField()