"""
URL configuration for proyecto project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from proyecto import views as vista

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', vista.login),
    path('', vista.login),
    path('panel/', vista.panel),
    path('registrarServidor/', vista.registrarServidor),
    path('verificar/', vista.verificar_otp_view),
    path('administrarServicios/', vista.administrar_servicios),
    path('levantarServicios/', vista.levantar_servicios),
    path('registro/', vista.registrar_usuario),
]
