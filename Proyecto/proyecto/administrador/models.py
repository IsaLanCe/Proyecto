from django.db import models
from django.utils import timezone
from datetime import timedelta

# Create your models here.
class Administrador(models.Model):
	user = models.CharField(max_length=20, unique=True)
	nombre = models.CharField(max_length=50)
	passwd = models.CharField(max_length=129)

class OTP(models.Model):
	code = models.CharField(max_length=6)
	created_at = models.DateTimeField(auto_now_add=True)
	esta_usado = models.BooleanField(default=False)

	def esta_expirado(self):
		return timezone.now() > self.created_at + timedelta(minutes=5)

