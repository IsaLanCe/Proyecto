from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.template import Template, Context
from administrador.models import Administrador
from . import hasher as hash


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