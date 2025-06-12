from django.db import models
from django.utils import timezone
from datetime import timedelta

# Create your models here.
class Administrador(models.Model):
	user = models.CharField(max_length=20, unique=True)
	nombre = models.CharField(max_length=50)
	passwdHash = models.BinaryField(max_length=60, default=b'')
	salt = models.BinaryField(max_length=29, default=b'')

class OTP(models.Model):
	code = models.CharField(max_length=10)
	created_at = models.DateTimeField(auto_now_add=True)
	esta_usado = models.BooleanField(default=False)

class ContadorIntentos(models.Model):
    ip = models.GenericIPAddressField(primary_key=True)
    contador = models.PositiveIntegerField()
    ultimo_intento = models.DateTimeField()

class Servidor(models.Model):
	dominio = models.CharField(primary_key=True, max_length=20)
	etiqueta = models.CharField(max_length=80)
	user = models.CharField(max_length=20)
	passwdHash = models.BinaryField(max_length=60, default=b'')
	salt = models.BinaryField(max_length=29, default=b'')

class Servicio(models.Model):
    nombre_completo = models.CharField(max_length=40, unique=True)
    fecha_instalacion = models.DateTimeField(auto_now_add=True)

class InstalacionServicio(models.Model):
    servidor = models.ForeignKey(Servidor, on_delete=models.CASCADE, to_field='dominio')
    servicio = models.ForeignKey(Servicio, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('servidor', 'servicio')
