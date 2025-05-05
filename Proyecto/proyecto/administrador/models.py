from django.db import models

# Create your models here.
class Administrador(models.Model):
	user = models.CharField(max_length=20, unique=True)
	nombre = models.CharField(max_length=50)
	passwd = models.CharField(max_length=129)

