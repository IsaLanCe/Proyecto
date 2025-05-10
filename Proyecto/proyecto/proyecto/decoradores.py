from django.shortcuts import redirect


def login_requerido(vista):
    def interna(request, *args, **kargs):
        if not request.session.get('logueado', False):
            return redirect('/login')
        return vista(request, *args, **kargs)
    return interna

def otp_requerido(vista):
    def interna(request, *args, **kargs):
        if not request.session.get('otp_sesion', False):
            return redirect('/login')
        return vista(request, *args, **kargs)
    return interna
