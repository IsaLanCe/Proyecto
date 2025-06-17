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
from administrador.models import Servidor
from administrador.models import Servicio
from administrador.models import ContadorIntentos
from administrador.models import InstalacionServicio
from datetime import datetime, timedelta
from proyecto import decoradores
import paramiko
import secrets
import ipaddress
import random
import string
import sys
import requests
import re
import os
import bcrypt
import logging


"""Configuración de bitacoras de nivel INFO

	Returns:
		_none_
	"""
logging.basicConfig(level=logging.INFO,
					filename='login.log',
					filemode='a',
					format='%(asctime)s - %(levelname)s - %(message)s',
					datefmt='%d-%b-%y %H:%M:%S')

class Servidor_No_Registrado(Exception):
    def __init__(self, *args) -> None:
        super().__init__(*args)

to = os.environ.get('TOKEN_T')
chat = os.environ.get('CHAT_ID')
tamanio = settings.TAMANIO_PASSWORD
size = settings.TAMANIO_OTP
tiempo_caducidad = settings.TIEMPO_CADUCIDAD_OTP

def get_client_ip(request):
    """_Funcion que recupera la solicitud hecha y regresa la direccion IP de origen_

	Args:
		request (_request_): _Recupera la solicitud_

	Returns:
		_ip_: _Regresa la direccion IP desde donde se hace la solicitud_
	"""

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def instalacion_no_registrada(servidor, servicio):
    """
    Retorna True si la combinación servidor-servicio NO está registrada.
    Retorna False si YA existe en la tabla InstalacionServicio.
    """
    return not InstalacionServicio.objects.filter(servidor=servidor, servicio=servicio).exists()


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

def servicio_no_registrado(nombre_servicio):
	"""_Funcion que verifica si el servicio que se quiere instalar no se encuentra registrado en la base de datos_

	Args:
		nombre_servicio (_str_): _Nombre del servicio que se quiere verificar_

	Returns:
		_Bool_: _Regresa Falso si el servicio si esta registrado y True si el servicio si esta registrado_
	"""
	return not Servicio.objects.filter(nombre_completo=nombre_servicio).exists()

def servicio_instalado_en_servidor(dominio, servicio):
	"""_Verifica si cierto servicio esta instalado en tal servidor_

	Args:
		dominio (_str_): _Dominio o IP del servidor donde se verificara_
		servicio (_str_): _Servicio que se va a verificar_

	Returns:
		_bool_: _Regresa True si el servicio ya esta instalado en ese servidor y False si el servicio no esta instalado en ese servidor_
	"""
	try:
		servidor = Servidor.objects.get(dominio=dominio)
		servicio = Servicio.objects.get(nombre_completo=servicio)
	except (Servidor.DoesNotExist, Servicio.DoesNotExist):
		return False
	return InstalacionServicio.objects.filter(servidor=servidor, servicio=servicio).exists()

def es_dominio_o_ip(cadena):
    cadena = cadena.strip()
    # Verifica si es una dirección IP (IPv4 o IPv6)
    try:
        ipaddress.ip_address(cadena)
        return True
    except ValueError:
        pass

    # Verifica si es un dominio válido
    dominio_regex = re.compile(
        r"^(?=.{1,253}$)(?!\-)([a-zA-Z0-9\-]{1,63}(?<!\-)\.)+[a-zA-Z]{2,63}$"
    )
    if dominio_regex.match(cadena):
        return True

    return False

def recaptcha_verify(recaptcha_response: str) -> bool:
    """_Funcion que verifica si se ha pasado el Recaptcha en el login de usuario_

	Args:
		recaptcha_response (str): _Respuesta que se envia al resolver el Recaptcha_

	Returns:
		bool: _Regresa True si el Recpatcha se ha pasado correctamente y regresa False si no se hizo_
	"""
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
		contrasena (_str_): Contraseña  a verificar

	Returns:
		bool: True si la contraseña contiene al menos una letra, False si es el caso contrario
	"""	
	return any(caracter.isalpha() for caracter in contrasena)

def contiene_numero(contrasena):
	""" Verifica si la contraseña contiene al menos un número

	Args:
		contrasena (_str_): Contraseña a verificar

	Returns:
		bool: True si la contraseña contiene al menos una letra, False si es el caso contrario
	"""    
	return any(c.isdigit() for c in contrasena)

def contiene_caracter_especial_seguro(contrasena):
    """_Funcion que verifica si la contraseña hace match con algun digito de la expresion regular_

	Args:
		contrasena (_str_): _Contraseña que se verificara_

	Returns:
		_bool_: _Regresa True si hay algun caracter especial en la contraseña y False si no hay ningun caracter especial en la contraseña_
	"""
    caracteres_permitidos = r"_$-"
    return any(c in caracteres_permitidos for c in contrasena)


def politica_tamanio_contrasena(contrasena):
	""" Verifica si la contraseña cumple con la longitud mínima requeridad (12 caracteres)

	Args:
		contrasena (_str_): Contraseña a valdiar

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
		contrasena (_str_): COntraseñ a averificar

	Returns:
		bool: True si la contraseña tiene al menos una letra mayúscula. False en caso contrario
	"""	
	return any(c.isupper() for c in contrasena)

def campo_vacio(campo):
	""" Verifica si un campo de texto está vacío o solo contiene espacios en blanco

	Args:
		campo (_str_): cadena a validar

	Returns:
		bool: True si el cmapo está vacío o solo contiene espacios. False en caso contrario
	"""    
	return campo.strip() == ''

def validar_campo(campo):
    """_Funcion que valida si un campo contiene digitos especiales_

	Args:
		campo (_str_): _Cadena que se envia para ser validada_

	Returns:
		_bool_: _Regresa True si la cadena no hace match con ningun caracter especial y false si hace con algun caracter_
	"""
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
	caracteres = string.ascii_letters + string.digits

	otp = ''.join(secrets.choice(caracteres) for _ in range(size))

	return otp

def eliminar_otps_anteriores():
	""" ELimina todos los registros anteriores del modelo OTP.
		Esta función se utiliza como limpieza previa antes de guardar un nuevo código OTP
	"""	
	tiempo = dj_timezone.now() - timedelta(minutes=tiempo_caducidad)
	OTP.objects.filter(Q(esta_usado=True) | Q(created_at__lt=tiempo)).delete()

def guardar_otp(code):
	""" Guarda un nuevo código OTP después de eliminar los anteriores

	Args:
		code (_str_): EL código OTP que se va a guardar.

	Returns:
		OTP: Instancia del modelo OTP recien creada.
	"""	
	eliminar_otps_anteriores()
	return OTP.objects.create(code=code)

def validad_caducidad_otp(fecha_creacion):
	""" Verifica si un código OTP ha caducado.
		Se considera que el OTP caduca si no ha pasado más de 1 min desde su creación.

	Args:
		fecha_creacion (_date_): Fecha y hora en la que se creó el OTP.

	Returns:
		bool: True si el OTP ha caducado, False si aún es válido
	"""	
	hora_actual = datetime.now(fecha_creacion.tzinfo)
	return hora_actual - fecha_creacion > timedelta(minutes=tiempo_caducidad)

def validar_tamanio_password(passwd):
	""" Verifica si la contraseña tiene al menos 12 caracteres.

	Args:
		passwd (_str_): COntraseña a validar. 

	Returns:
		bool: True si la contraseña tiene menos de 12 caracteres. False en caso contrario. 
	"""	
	if len(passwd) < tamanio:
		return True
	else:
		return False

def enviar_otp_telegram(code):
	"""_Funcion que envia un codigo OTP por telegram que es generado aleatoriamente y almacenado en la base de datos_

	Args:
		code (_str_): _Codigo OTP que se enviara por telegram_

	Returns:
		_bool_: _Regresa True si todo salio exitoso y False si hubo algun error_
	"""
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
	"""_Funcion que elimina la sesion actual_

	Args:
		request (_request_): _Peticion actual_

	Returns:
		_redirect_: _Redigire a otra pestaña_
	"""
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
		
		if validar_campo(usuario):
			errores.append("El nombre de usuario no debe contener caracteres especiales")
		
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
					mensaje = f"Loggin correcto del usuario {usuario}"
					logging.info(mensaje)
					return redirect('/verificar')
				else:
					errores.append("Usuario y/o Contraseña incorrecta")
					mensaje = f"Loggin incorrecto del usuario {usuario}"
					logging.info(mensaje)
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
	errores = []
	if request.method == 'GET':
		try:
			servidores = Servidor.objects.all().prefetch_related('instalacionservicio_set__servicio')
		except Exception as e:
			errores.append("Error al leer la base de datos")

		if errores:
			return render(request, p, {'errores': errores})
		else:
			return render(request, p, {'servidores': servidores})
	elif request.method == 'POST':
		return render(request, p)
	
@decoradores.login_requerido
@decoradores.token_requerido		
def registrarServidor(request):
	r = 'registroServidor.html'
	errores = []
	if request.method == 'GET':
		return render(request, r)
	elif request.method == 'POST':
		dominio = request.POST.get('domain', '')
		etiqueta = request.POST.get('server','')
		usuario = request.POST.get('user','')
		password = request.POST.get('pass','')
		password2 = request.POST.get('pass2','')

		#Verificar que los campos no se envien vacios
		if campo_vacio(dominio):
			errores.append("El dominio no debe estar vacio")
		if campo_vacio(etiqueta):
			errores.append("La descripcion del servidor no debe estar vacia")
		if campo_vacio(usuario):
			errores.append("El usuario no debe estar vacio")
		if campo_vacio(password):
			errores.append("La contraseña no debe estar vacia")
		if campo_vacio(password2):
			errores.append("La validación de contraseña no debe estar vacio")
		
		#Verificación del dominio o IP
		if not es_dominio_o_ip(dominio):
			errores.append("El dominio o IP no tiene el formato correcto")
		
		#Validad el username y contraseña
		if validar_campo(etiqueta):
			errores.append("La descripcion del servidor no debe contener caracteres especiales")
		if validar_campo(usuario):
			errores.append("El nombre de usuario no debe contener caracteres especiales")
		if validar_campo(password):
			errores.append("La contraseña no debe tener caracteres especiales")
		if validar_campo(password2):
			errores.append("La validación de contraseña no debe tener caracteres especiales")
		
		if password != password2:
			errores.append("Las contraseñas y la validación no coinciden")

		if errores:
			return render(request, r, {'errores':errores})
		else:
			try:
				password = password.encode('utf-8')
				salt = bcrypt.gensalt()
				hash = bcrypt.hashpw(password,salt)

				user = Servidor(
					dominio = dominio,
					etiqueta = etiqueta,
					user = usuario,
					passwdHash = hash,
					salt = salt
				)
				user.save()
				mensaje = "Servidor registrado correctamente"
				from datetime import datetime
				fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
				mensajeLog = f"---Servidor registrado por el usuario {usuario}: {fecha}"
				logging.info(mensajeLog)
				return render(request, r, {'mensaje': mensaje})
			except Exception as e:
				errores.append("Error de conexion")	
				return render (request, r, {'errores': errores})


@decoradores.login_requerido
@decoradores.token_requerido
def administrar_servicios(request):
	template = 'administrar_servicios.html'
	errores = []

	if request.method == 'GET':
		return render (request, template)
	elif request.method == 'POST':
		dominio = request.POST.get('domain')
		servicio = request.POST.get('servicio')
		accion = request.POST.get('accion')
		usuario = request.POST.get('user')
		password = request.POST.get('pass')

		try:
			servidor_obj = Servidor.objects.get(dominio=dominio)
		except Servidor.DoesNotExist:
			errores.append("El servidor no se encuentra registrado en la base de datos")
			return render(request, template, {'errores': errores})
		
		if servidor_obj.user != usuario or not bcrypt.checkpw(password.encode(), servidor_obj.passwdHash):
			errores.append("El usuario o la contraseña del servidor no son correctas")
			return render (request, template, {'errores': errores})
		
		if servicio_instalado_en_servidor(dominio, servicio):
			try:
				ssh = paramiko.SSHClient()
				ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				ssh.connect(hostname=dominio, username=usuario, password=password, port=22, timeout=10)

				comando = f"echo {password} | sudo -S systemctl {accion} {servicio}"
				_, stdout, stderr = ssh.exec_command(comando)

				error = stderr.read().decode()
				ssh.close()
			except Exception as e:
				errores.append("Error al establecer conexion con el servidor")
		else:
			errores.append("El servicio no esta instalado en el servidor")

		if errores:
			return render(request, template, {'errores': errores})
		else:
			mensaje = f"Exito de {accion} en el servicio {servicio}"
			fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
			mensajeLog = f"+++Servicio {servicio} {accion} por el usuario {usuario}: {fecha}"
			logging.info(mensajeLog)
			return render(request, template, {'mensaje': mensaje})
    

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
    template = 'levantar_servicios.html'
    errores = []

    if request.method == 'GET':
        return render(request, template)
    elif request.method == 'POST':
        dominio = request.POST.get('domain')
        servicio = request.POST.get('servicio')
        usuario = request.POST.get('user')
        password = request.POST.get('pass')

        try:
            objetivo = Servidor.objects.get(dominio=dominio)

            usuarioServidor = objetivo.user
            passwdHash = objetivo.passwdHash  
        except Servidor.DoesNotExist:
            errores.append("El servidor no se encuentra registrado en la base de datos")
            return render(request, template, {'errores': errores})

        if usuarioServidor != usuario or not bcrypt.checkpw(password.encode(), passwdHash):
            errores.append("El usuario o la contraseña del servidor no son correctos")
            return render(request, template, {'errores': errores})

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=dominio, username=usuario, password=password, port=22, timeout=10)
            comando = 	f"echo {password} | sudo -S apt install -y {servicio}"
            stdin, stdout, stderr = ssh.exec_command(comando)

            salida = stdout.read().decode()
            error = stderr.read().decode()
            ssh.close()

			  # Verificar si hubo error durante la instalación
            if error and "Error:" in error:
                errores.append("Servicio no encontrado")
            elif servicio_no_registrado(servicio):
                try:
                    nuevo_servicio = Servicio(nombre_completo=servicio)
                    nuevo_servicio.save()
                except Exception as e:
                    errores.append("Error al guardar el registro")

        except Exception as e:
            errores.append(f"Error al establecer conexión con el servidor: {str(e)}")

        try:
            servicio_obj = Servicio.objects.get(nombre_completo=servicio)
            servicio_id = servicio_obj.id
        except Servicio.DoesNotExist:
           errores.append("El servicio especificado no está registrado en la base de datos")

        if instalacion_no_registrada(objetivo.dominio, servicio_id):
           InstalacionServicio.objects.create(servidor=objetivo, servicio=servicio_obj)
        else:
           errores.append("El servicio ya se encuentra registrado en ese servidor")

        if errores:
           return render(request, template, {'errores': errores})
        else:
            fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
            mensajeLog = f"***Servicio {servicio} instalado correctamente en servidor {dominio} por el usuario {usuario}: {fecha}"
            logging.info(mensajeLog)
            mensaje = "Exito en el proceso"
            return render(request, template, {'mensaje': mensaje})
