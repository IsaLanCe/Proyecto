import hashlib
import base64

def hashearPassword(password_original: str, salt: bytes):
    password_original_bytes = password_original.encode('utf-8')
    password_bytes = password_original_bytes+salt
    hasher = hashlib.sha512()
    hasher.update(password_bytes)
    hash_bd = hasher.hexdigest()
    return hash_bd

def verificarPassword(password: str, hash_bd: str, salt_almacenado: bytes):
    # Codificar el password ingresado y agregar el salt
    password_bytes = password.encode('utf-8') + salt_almacenado
    # Generar el hash del password ingresado
    hasher = hashlib.sha512()
    hasher.update(password_bytes)
    mi_hash = hasher.hexdigest()
    # Comparar con el hash almacenado
    return mi_hash == hash_bd

