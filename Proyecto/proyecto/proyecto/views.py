from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.template import Template, Context
from administrador.models import Administrador
from administrador.models import OTP
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

def campo_vacio(campo):
    return campo.strip() == ''

def validar_campo(campo):
    if re.match(r'^[a-zA-Z0-9]+$', campo):
        return False
    else:
        return True
	
def generar_otp():
	size = 10
	otp = ''.join([random.choice( string.ascii_uppercase + string.ascii_lowercase + string.digits ) for n in range(size)])

	return otp

def eliminar_otps_anteriores():
	OTP.objects.all().delete()

def guardar_otp(code):
	eliminar_otps_anteriores()
	return OTP.objects.create(code=code)

def validad_caducidad_otp(fecha_creacion):
	hora_actual = datetime.now(fecha_creacion.tzinfo)
	return hora_actual - fecha_creacion > timedelta(minutes=1)

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
					errores.append("El codigo de verificación expiro")
				elif otp.code == otp_input:
					request.session['autorizado'] = True
					return redirect('/panel')
				else:
					errores.append("Logueate denuevo en la pagina")
					return redirect('/login')
			except OTP.DoesNotExist:
				errores.append("Error. Solicite denuevo la pagina")
		
		if errores:
			request.session['logueado'] = False
			request.session['usuario'] = ''
			return render(request, l, {'errores': errores})
		else:
			return redirect('/panel')	

@decoradores.login_requerido
@decoradores.token_requerido
def levantar_servicios(request):
	l = 'levantar_servicios.html'
	return render (request, l)
	