from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.conf import settings
from django.template import Template, Context
from django.utils import timezone as dj_timezone
from datetime import timezone as dt_timezone
from datetime import datetime
from django.db.models import Q
from administrador.models import Administrador
from administrador.models import OTP
from administrador.models import ContadorIntentos
from datetime import datetime, timedelta
from proyecto import decoradores
from . import hasher as hash
import random
import string
import sys
import requests
import re
import os
import bcrypt

to = os.environ.get('TOKEN_T')
chat = os.environ.get('CHAT_ID')
tamanio = settings.TAMANIO_PASSWORD
size = settings.TAMANIO_OTP
tiempo_caducidad = settings.TIEMPO_CADUCIDAD_OTP
#tiempo_limite = settings.TIEMPO_REGISTRO

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def ip_registrada(ip: str) -> bool:
    """
    True si la IP ya está en la BD.

    ip
    returns: bool 
    """
    try:
        ContadorIntentos.objects.get(pk=ip)
        return True
    except:
        return False

def fecha_en_ventana(fecha, segundos_ventana=settings.SEGUNDOS_INTENTO) -> bool:
    """
    True si la fecha está en la ventana de tiempo.

    fecha
    returns: bool 
    """
    actual = datetime.now(dt_timezone.utc)
    diferencia = (actual - fecha).seconds
    return diferencia <= segundos_ventana
    
def tienes_intentos_login(request) -> bool:
    """
    Verdadero si puedes seguir intentando loguearte.

    request
    returns: bool 
    """
    ip = get_client_ip(request)
    if not ip_registrada(ip):
        registro = ContadorIntentos()
        registro.ip = ip
        registro.contador = 1
        registro.ultimo_intento = datetime.now(dt_timezone.utc)
        registro.save()
        return True

    registro = ContadorIntentos.objects.get(pk=ip)
    fecha = registro.ultimo_intento
    if not fecha_en_ventana(fecha):
        registro.contador = 1
        registro.ultimo_intento = datetime.now(dt_timezone.utc)
        registro.save()
        return True

    if registro.contador < settings.NUMERO_INTENTOS:
        registro.contador += 1
        registro.ultimo_intento = datetime.now(dt_timezone.utc)
        registro.save()
        return True

    registro.ultimo_intento = datetime.now(dt_timezone.utc)
    registro.save()
    return False


def recaptcha_verify(recaptcha_response: str) -> bool:

    data = {
      "secret": settings.RECAPTCHA_PRIVATE_KEY,
      "response": recaptcha_response
    }

    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    return result.get('success', False)


def contiene_letra(contrasena):
	"""Verifica si la contraseña contiene al menos una letra

	Args:
		contrasena (_type_): Contraseña  a verificar

	Returns:
		bool: True si la contraseña contiene al menos una letra, False si es el caso contrario
	"""	
	return any(caracter.isalpha() for caracter in contrasena)

def contiene_numero(contrasena):
	""" Verifica si la contraseña contiene al menos un número

	Args:
		contrasena (_type_): COntraseña a verificar

	Returns:
		bool: True si la contraseña contiene al menos una letra, False si es el caso contrario
	"""    
	return any(c.isdigit() for c in contrasena)

def contiene_caracter_especial_seguro(contrasena):
    caracteres_permitidos = r"_$-"
    return any(c in caracteres_permitidos for c in contrasena)

def politica_tamanio_contrasena(contrasena):
	""" Verifica si la contraseña cumple con la longitud mínima requeridad (12 caracteres)

	Args:
		contrasena (_type_): COntraseña a valdiar

	Returns:
		bool: True si la contraseña tiene menos de 12 caracteres. False en caso contrario
	"""	
	if len(contrasena) < tamanio:
		return  True
	else:
		return False

def tiene_mayuscula(contrasena):
	""" Verifica si la contraseña contiene al menos una letra mayúscula

	Args:
		contrasena (_type_): COntraseñ a averificar

	Returns:
		bool: True si la contraseña tiene al menos una letra mayúscula. False en caso contrario
	"""	
	return any(c.isupper() for c in contrasena)

def campo_vacio(campo):
	""" Verifica si un campo de texto está vacío o solo contiene espacios en blanco

	Args:
		campo (_type_): cadena a validar

	Returns:
		bool: True si el cmapo está vacío o solo contiene espacios. False en caso contrario
	"""    
	return campo.strip() == ''

def validar_campo(campo):
    if re.match(r'^[a-zA-Z0-9 _-]+$', campo):
        return False
    else:
        return True
	
def generar_otp():
	"""Genera un código OTP (One-Time Password) aleatorio de 10 carcateres.
	EL código incluye letras mayúsculas, minúsculas y números

	Returns:
		str: Cadena OTP generada aleatoriamente.
	"""	
	otp = ''.join([random.choice( string.ascii_uppercase + string.ascii_lowercase + string.digits ) for n in range(size)])

	return otp

def eliminar_otps_anteriores():
	""" ELimina todos los registros anteriores del modelo OTP.
		Esta función se utiliza como limpieza previa antes de guardar un nuevo código OTP
	"""	
	tiempo = dj_timezone.now() - timedelta(minutes=3)
	OTP.objects.filter(Q(esta_usado=True) | Q(created_at__lt=tiempo)).delete()

def guardar_otp(code):
	""" Guarda un nuevo código OTP después de eliminar los anteriores

	Args:
		code (_type_): EL código OTP que se va a guardar.

	Returns:
		OTP: Instancia del modelo OTP recien creada.
	"""	
	eliminar_otps_anteriores()
	return OTP.objects.create(code=code)

def validad_caducidad_otp(fecha_creacion):
	""" Verifica si un código OTP ha caducado.
		Se considera que el OTP caduca si no ha pasado más de 1 min desde su creación.

	Args:
		fecha_creacion (_type_): Fecha y hora en la que se creó el OTP.

	Returns:
		bool: True si el OTP ha caducado, False si aún es válido
	"""	
	hora_actual = datetime.now(fecha_creacion.tzinfo)
	return hora_actual - fecha_creacion > timedelta(minutes=tiempo_caducidad)

def validar_tamanio_password(passwd):
	""" Verifica si la contraseña tiene al menos 12 caracteres.

	Args:
		passwd (_type_): COntraseña a validar. 

	Returns:
		bool: True si la contraseña tiene menos de 12 caracteres. False en caso contrario. 
	"""	
	if len(passwd) < tamanio:
		return True
	else:
		return False

def enviar_otp_telegram(code):
	
	token = to
	chat_id = chat
	url = f'https://api.telegram.org/bot{token}/sendMessage'
	mensaje = f"Tu token de validación es: {code}"
    
	datos = {
		'chat_id':chat_id,
		'text':mensaje,
		'parse_mode':'Markdown'
	}

	try:
		response = requests.post(url, data=datos)
		response.raise_for_status()
		return True
	except requests.RequestException as e:
		print(f'Error: {e}')
		return False

def logout(request):

	request.session['logueado'] = False
	request.session['autorizado'] = False
	request.session.flush()
	return redirect('/login')
   

def login(request):
	t = "login.html"
	errores = []
	if request.method == 'GET':
		request.session['logueado'] = False
		request.session['usuario'] = ''
		return render(request,"login.html")
	elif request.method == 'POST':
		usuario = request.POST.get('usuario','')
		passwd = request.POST.get('passwd','').encode('utf-8')
		captcha_token = request.POST.get('g-recaptcha-response', '').strip()
		
		if not captcha_token or not recaptcha_verify(captcha_token):
			errores.append("Captcha no autorizado")
		
		if not tienes_intentos_login(request):
			error = 'Debes esperar %s segundo antes de volver a intentar' % settings.SEGUNDOS_INTENTO
			errores.append(error)

		if errores:
			return render(request, t , {'errores':errores})
		else:

			try:
				admin_bd = Administrador.objects.get(user=usuario)
				user_bd = admin_bd.user
				passwd_bd = admin_bd.passwdHash

				if bcrypt.checkpw(passwd, passwd_bd):
					request.session['logueado'] = True
					request.session['usuario'] = usuario
					code = generar_otp()
					guardar_otp(code)
					enviar_otp_telegram(code)
					return redirect('/verificar')
				else:
					errores.append("Usuario y/o Contraseña incorrecta")
					return render(request, 'login.html', {'errores': errores})
			except Administrador.DoesNotExist:
				errores.append("Usuario no encontrado")
			except Exception as e:
				errores.append(f"Error interno: {str(e)}")

			if errores:
				return render(request, 'login.html', {'errores':errores})

@decoradores.login_requerido
@decoradores.token_requerido		
def panel(request):
	p = 'panel.html'
	if request.method == 'GET':
		return render(request,'panel.html')

@decoradores.login_requerido
@decoradores.token_requerido		
def registrarServidor(request):
	r = 'registroServidor.html'
	if request.method == 'GET':
		return render(request, r)

@decoradores.login_requerido
@decoradores.token_requerido
def administrar_servicios(request):
	a = 'administrar_servicios.html'
	return render(request, a)


@decoradores.login_requerido
def verificar_otp_view(request):
	errores = []
	v = 'verificar_otp.html'
	l = 'login.html'
	if request.method == 'GET':
		return render (request,v)
	elif request.method == 'POST':
		otp_input = request.POST.get('otp','')
		longitud_otp = 10
		if campo_vacio(otp_input):
			errores.append("El codigo de verificación es obligatorio")
		elif validar_campo(otp_input):
			errores.append("No debe tener caracteres especiales")
		elif len(otp_input)<longitud_otp or len(otp_input) >longitud_otp:
			errores.append("La longitud del codigo de verificación debe ser de 10 digitos")
		else:
			try:
				otp = OTP.objects.get(code=otp_input)
				if validad_caducidad_otp(otp.created_at):
					errores.append("El código de verificación expiro")
					#otp.esta_usado == True
				elif otp.esta_usado == False:
					otp.esta_usado = True
					otp.save()
					request.session['autorizado'] = True
					return redirect('/panel')
				else:
					errores.append("Código de verificación ya usado o mal pasado")
					return redirect('/login')
			except OTP.DoesNotExist:
				errores.append("Error. Solicite denuevo la pagina")
		
		if errores:
			request.session['logueado'] = False
			request.session['usuario'] = ''
			return render(request, l, {'errores': errores})
		else:
			return redirect('/panel')	

def registrar_usuario(request):
	r = 'registrar.html'
	errores = []
	if request.method == 'GET':
		return render (request,r)
	elif request.method == 'POST':
		username = request.POST.get('user', '')
		nombre = request.POST.get('nombre','')
		passwd = request.POST.get('passwd','')
		passwd2 = request.POST.get('passwd2','')
		
		if campo_vacio(username):
			errores.append("El username no debe estar vacio")
		if campo_vacio(nombre):
			errores.append("El nombre no debe ir vacio")
		if campo_vacio(passwd):
			errores.append("La contraseña no debe ir vacia")
		if campo_vacio(passwd2):
			errores.append("La confirmacion de contraseña no debe ir vacia")

		###Validaciones base para los demas campos
		if validar_campo(username):
			errores.append("El username no debe contener caracteres especiales")
		if validar_campo(nombre):
			errores.append("El nombre no debe contener caracteres especiales")
		
		##Validaciones explicitas para contraseñas
		#Verifica la longitud de las contraseñas
		if politica_tamanio_contrasena(passwd):
			errores.append("La contraseña debe tener al menos 12 caracteres")
		if politica_tamanio_contrasena(passwd2):
			errores.append("La validación de contraseña debe tener al menos 12 caracteres")
		
		#Valida si tiene algun digito especial seguro
		if not contiene_caracter_especial_seguro(passwd):
			errores.append("La contraseña debe contener algun caracter especial. Caracteres permitidos: _ - $")
		if not contiene_caracter_especial_seguro(passwd2):
			errores.append("La contraseña debe contener algun caracter especial. Caracteres permitidos: _ - $")

		#Verifica si tiene letra minuscula
		if not contiene_letra(passwd):
			errores.append("La contraseña debe tener letras al menos una minuscula")
		if not contiene_letra(passwd2):
			errores.append("La validación de contraseña debe tener al menos una letra minuscula")
		
		#Valida si tiene una mayuscula	
		if not tiene_mayuscula(passwd):
			errores.append("La contraseña debe tener al menos una mayuscula")
		if not tiene_mayuscula(passwd2):
			errores.append("La validación de contraseña debe tener el menos una mayuscula")
		
		#Valida si tiene un numero
		if not contiene_numero(passwd):
			errores.append("La contraseña debe tener al menos un numero")
		if not contiene_numero(passwd2):
			errores.append("La validación de contraseña debe tener al menos un numero")

		if passwd != passwd2:
			errores.append("Las contraseñas no son iguales")

		if errores:
			return render(request, r, {'errores': errores})
		else:
			try:	
				passwd = passwd.encode('utf-8')
				salt = bcrypt.gensalt()
				hash = bcrypt.hashpw(passwd,salt)

				admin = Administrador(
				user = username,
				nombre = nombre,
				passwdHash = hash,
				salt = salt
				)
				admin.save()
				return redirect ('/login')
			except Exception as e:
				errores.append(f"Error interno: {str(e)}")	
				return render (request, r, {'errores': errores})

@decoradores.login_requerido
@decoradores.token_requerido
def levantar_servicios(request):
	l = 'levantar_servicios.html'
	return render (request, l)
	
