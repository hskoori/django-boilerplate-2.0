from apps.user_account.models import User
from rest_framework import permissions
import random
from apps.main.functions import get_client_ip
from .models import LoginHistory
import datetime




def validate_email(email):
    account = None
    try:
        account = User.objects.get(email=email,email_verified=True)
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
        account = User.objects.get(phone=phone,phone_verified=True)
    except User.DoesNotExist:
        return None
    if account != None:
        return phone
    

def get_new_username():
    try:
        last_username = User.objects.all().order_by("date_joined").last().username
        return str(int(last_username) + 1)
    except:
        return "1"

    

def send_phone_otp(country_code,phone,otp):
    # sendSMS(apikey, numbers, sender, message)
    print("Your OTP is : " ,str(otp))


def send_email_otp(email,otp):
    
    # sendSMS(apikey, numbers, sender, message)
    print("Your OTP is : " ,str(otp))



def random_password(length):
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "0123456789"
    symbols = "@#$&_-()=%*:/!?+."

    string = lower + upper + numbers + symbols
    password = "".join(random.sample(string, length))
    return password


def save_login_history(request,user,login_method):
    LoginHistory.objects.create(
        user = user,
        ip_address=get_client_ip(request),
        login_method = login_method
    )
    user.last_login = datetime.datetime.now()
    user.save()



class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_admin:
            return True
        return False

