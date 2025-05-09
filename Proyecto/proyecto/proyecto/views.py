from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.template import Template, Context
from administrador.models import Administrador
from . import hasher as hash
import random
import string


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

def generar_otp():
	size = 6
	otp = ''.join([random.choice( string.ascii_uppercase + string.ascii_lowercase + string.digits ) for n in range(size)])

	return otp

def eliminar_otps_anteriores():
	#OTP.objects.all().delete()
	print("")

def guardar_otp():
	eliminar_otps_anteriores()
	return OTP.objects.create(code=code)

def enviar_otp_telegram(code):
	token = "Hola"
	chat_id = "Adios"
	mensaje = f"Tu codigo de verificación es: {code}"

def generar_otp_view(request):
	v = 'verificar_otp.html'
	code = generar_otp()
	guardar_otp(code)
	enviar_otp_telegram(code)
	return redirect(v)

def verificar_otp_view(request):
	errores = []

	if request.method == 'POST':
		otp_input = request.POST.get('otp')
		if not otp_input:
			errores.append("El codigo de verificación es obligatorio")
		else:
			try:
				otp = OTP.objects.get(code=otp_input, is_used=False)

				if otp.esta_expirado():
					errores.append("El codigo de verificación ha expirado")
				else:
					otp.esta_usado = True
					otp.save()
					return redirect()
			except OTP.DoesNotExist:
				errores.append("El codigo es incorrecto o ya fue usado")

	return render(request, 'verificar_otp.html', {'errores':errores})
	