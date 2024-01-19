from apps.user_account.models import User
from random import randint

from rest_framework import permissions







def validate_email(email):
    account = None
    try:
        account = User.objects.get(email=email)
    except User.DoesNotExist:
        return None
    if account != None:
        return email

def validate_username(username):
    account = None
    try:
        account = User.objects.get(username=username)
    except User.DoesNotExist:
        return None
    if account != None:
        return username
def validate_phone(phone):
    account = None
    try:
        account = User.objects.get(phone=phone)
    except User.DoesNotExist:
        return None
    if account != None:
        return phone

# def send_otp(phone):
#     otp=randint(1000,9999)
#     return otp

    # if phone:

    #     otp = randint(1000,9999)
    #     phone = str(phone)
    #     otp_key = str(key)

    #     link = f'https://2factor.in/API/R1/?module=TRANS_SMS&apikey=7c59cf94-d129-11ec-9c12-0200cd936042&to={phone}&from=MMBook&templatename=mymedbook&var1={otp_key}&var2={otp_key}'

    #     result = requests.get(link, verify=False)

    #     return otp_key
    # else:
    #     return False

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_admin:
            return True
        return False
