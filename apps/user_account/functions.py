from apps.user_account.models import User
from rest_framework import permissions
import random
from apps.main.functions import get_client_ip
from .models import LoginHistory
import datetime




def validate_email(email):
    try:
        if(User.objects.filter(email=email,email_verified=True).exists()):
            return False
        else:
            return True
    except User.DoesNotExist:
        return True
    except:
        return False

def validate_username(username):
    try:
        if(User.objects.filter(username=username).exists()):
            return False
        else:
            return True
    except User.DoesNotExist:
        return True
    except:
        return False
    
def validate_phone(country_code,phone):
    try:
        if(User.objects.filter(country_code=country_code, phone=phone,phone_verified=True).exists()):
            return False
        else:
            return True
    except User.DoesNotExist:
        return True
    except:
        return False



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

