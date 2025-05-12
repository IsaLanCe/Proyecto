from django.shortcuts import redirect
from functools import wraps


def login_requerido(vista):
    @wraps(vista)
    def interna(request, *args, **kargs):
        if not request.session.get('logueado', False):
            return redirect('/login')
        return vista(request, *args, **kargs)
    return interna


