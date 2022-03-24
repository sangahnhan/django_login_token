import json

from django.views           import View
from django.http            import JsonResponse
from django.core.exceptions import ValidationError

from users.models    import User
from cores.validator import *

class SignUpView(View):
    def post(self,request):
        try:
            data         = json.loads(request.body)
            name         = data['name']
            email        = data['email']
            password     = data['password']
            phone_number = data['phone_number']
            etc_info     = data['etc_info']

            validate_email(email)
            check_email_duplication(email)
            validate_password(password)

            password_encrypt = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            User.objects.create(
                    name         = name,    
                    email        = email,
                    password     = password_encrypt,
                    phone_number = phone_number,
                    etc_info     = etc_info
            )
            return JsonResponse({'message' : 'SUCCESS'} , status=201)
        except KeyError:
            return JsonResponse({'message' : 'KEY_ERROR'} , status=400)
        except ValidationError as e:
            return JsonResponse({'message' : e.message} , status=400)

class SignInView(View):
    def post(self,request):
        try:
            data     = json.loads(request.body)
            email    = data['email']
            password = data['password']

            if not User.objects.filter(email = email, password = password).exsists(): 
                return JsonResponse({'message' : 'INVALID_USER'}, status=401)
            return JsonResponse({'message' : 'LOGIN SUCCESS'}, status=200)
        except KeyError:
            return JsonResponse({"message" : "KEY_ERROR"} , status=400)