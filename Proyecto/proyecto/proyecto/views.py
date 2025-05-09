from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.template import Template, Context
from administrador.models import Administrador
from administrador.models import OTP
from . import hasher as hash
import random
import string
import sys
import requests
import re
import os

to = os.environ.get('TOKEN_T')
chat = os.environ.get('CHAT_ID')

def campo_vacio(campo):
    return campo.strip() == ''

def validar_campo(campo):
    if re.match(r'^[a-zA-Z0-9 _-]+$', campo):
        return False
    else:
        return True
	
def generar_otp():
	size = 6
	otp = ''.join([random.choice( string.ascii_uppercase + string.ascii_lowercase + string.digits ) for n in range(size)])

	return otp

def eliminar_otps_anteriores():
	OTP.objects.all().delete()

def guardar_otp(code):
	eliminar_otps_anteriores()
	return OTP.objects.create(code=code)

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
		passwd = request.POST.get('passwd','')

		try:
			admin_bd = Administrador.objects.get(user=usuario)
			user_bd = admin_bd.user
			passwd_bd = admin_bd.passwd


			if user_bd == usuario and passwd == passwd_bd:
				request.session['logueado'] = True
				request.session['usuario'] = usuario
				return redirect('/panel')
			else:
				errores.append("Usuario y/o Contraseña incorrecta")
				return render(request, 'login.html', {'errores': errores})
		except:
			errores.append("Lo sentimos, hubo una falla")
			return render(request, 'login.html', {'errores':errores})
		
def panel(request):
	p = 'panel.html'
	if request.method == 'GET':
		return render(request,'panel.html')
	
def registrarServidor(request):
	r = 'registroServidor.html'
	if request.method == 'GET':
		return render(request, r)
	
def administrar_servicios(request):
	a = 'administrar_servicios.html'
	if request.method == 'GET':
		return render(request,a)

def generar_otp_view(request):
	v = 'verificar_otp.html'
	if request.method == 'POST':
		return render(request,v)
	elif request.method == 'GET':
		code = generar_otp()
		guardar_otp(code)
		enviar_otp_telegram(code)
		return render(request, v)

def verificar_otp_view(request):
	errores = []
	v = 'verificar_otp.html'
	a = 'administrar_servicios.html'

	if request.method == 'POST':
		otp_input = request.POST.get('otp')
		if campo_vacio(otp_input):
			errores.append("El codigo de verificación es obligatorio")
		elif validar_campo(otp_input):
			errores.append("No debe tener caracteres especiales")
		else:
			try:
				otp = OTP.objects.get(code=otp_input, esta_usado=False)

				if otp.esta_expirado():
					errores.append("El codigo de verificación ha expirado")
				else:
					otp.esta_usado = True
					otp.save()
					return redirect()
			except OTP.DoesNotExist:
				errores.append("El codigo es incorrecto o ya fue usado")

	return render(request, 'verificar_otp.html', {'errores':errores})
	