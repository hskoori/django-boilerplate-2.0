from django.contrib.auth import get_user_model
from rest_framework import status
from random import randint
from apps.user_account.models import User ,LoginHistory


from rest_framework.decorators import action
from django.contrib.auth import authenticate, login
from rest_framework.permissions import AllowAny,IsAuthenticated
from apps.user_account.functions import validate_email,IsAdmin,send_phone_otp,send_email_otp,validate_phone,random_password,save_login_history
# from rest_framework.authentication import SessionAuthentication
from django.contrib.sessions.models import Session
from rest_framework.viewsets import  ModelViewSet
from rest_framework.response import Response
from rest_framework.decorators import api_view,parser_classes,permission_classes,authentication_classes
from rest_framework.parsers import JSONParser,FormParser, MultiPartParser,FileUploadParser
from .serializers import (
    UserSerializer,
    PasswordResetSerializer,
    LoginHistorySerializer
    )
from rest_framework.authtoken.models import Token
from django.contrib.sessions.backends.db import SessionStore
from datetime import datetime
from django.views.decorators.csrf import csrf_exempt
from rest_framework.filters import SearchFilter

User = get_user_model()

# from rest_framework.generics import (
#     # ListAPIView,
#     RetrieveUpdateAPIView,
#     # RetrieveUpdateDestroyAPIView,
# )


class UserViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    queryset = User.objects.all()
    lookup_field = "username"
    filter_backends = [SearchFilter]
    search_fields = ['username','phone','email','full_name']

    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            return User.objects.all()
        else:
            return User.objects.filter(pk=user.pk)

    def get_permissions(self):
        if self.action == 'destroy':
            permission_classes = [IsAdmin]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]



    # def get_permissions(self):
    #     if self.action in ['destroy', 'update']:
    #         permission_classes = [IsAdmin]
    #     else:
    #         permission_classes = [IsAuthenticated]
    #     return [permission() for permission in permission_classes]


    # def get_queryset(self, *args, **kwargs):
    #     assert isinstance(self.request.user.id, int)
    #     return self.queryset.filter(id=self.request.user.id)

    # @action(detail=False)
    # def me(self, request):
    #     serializer = UserSerializer(request.user, context={"request": request})
    #     return Response(status=status.HTTP_200_OK, data=serializer.data)
    
    # # def create(self, request, *args, **kwargs):
    # #     serializer = self.get_serializer(data=request.data)
    # #     serializer.is_valid(raise_exception=True)
    # #     self.perform_create(serializer)
    # #     headers = self.get_success_headers(serializer.data)
    # #     return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    # def perform_create(self, serializer):
    #     serializer.save()








# @csrf_exempt
# @api_view(['POST',])
# @permission_classes((IsAdmin, ))
# @parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
# def registration_view(request):
#     status_code=status.HTTP_400_BAD_REQUEST
#     if request.method == 'POST':
#         data = {}
#         email = request.data.get('email', '0').lower() 
#         if validate_email(email) != None:
#             data['error_message'] = 'That email is already in use.'
#             data['response'] = 'Error'
#             return Response(data)

#         username = request.data.get('username', '0')
#         if validate_username(username) != None:
#             data['error_message'] = 'That username is already in use.'
#             data['response'] = 'Error'  
#             return Response(data)
#         request_data = request.data.copy()
#         serializer = UserSerializer(data=request_data)
#         if serializer.is_valid():
#             user = serializer.save()
#             data['response'] = 'successfully registered new user.'
#             data['email'] = user.email
#             user.email_verified=True

#             user.phone_verified=True
#             user.is_admin=True
#             user.is_superuser=True
#             user.save()
#             data['username'] = user.username
#             try:
#                 token = Token.objects.get(user=user).key
#             except Token.DoesNotExist:
#                 token = Token.objects.create(user=user).key
#             save_login_history(request,user,"registerd by admin")
#             data['token'] = token
#             status_code=status.HTTP_200_OK
#         else:
#             data = serializer.errors
#         return Response(data,status=status_code)





# >>>>> Register with phone number <<<<<<<<<
# >>>>> Register with phone number <<<<<<<<<
@api_view(['POST',])
@permission_classes((AllowAny, ))
# @authentication_classes([SessionAuthentication])
@parser_classes([JSONParser, FormParser, MultiPartParser, FileUploadParser])
def registration_phone(request):
    status_code = status.HTTP_400_BAD_REQUEST
    if request.method == 'POST':
        data = {}
        phone = request.data.get('phone', '0')
        country_code = request.data.get('country_code', '0')
        request_data = request.data.copy()
        serializer = UserSerializer(data=request_data)
        request_data['password'] = request_data['password'] if 'password' in request_data else random_password(16)

        if serializer.is_valid():
            status_code = status.HTTP_200_OK
            data = serializer.data
            if(validate_phone(country_code,phone)):
                data['status'] = 'success'
                data['message'] = 'User registration successful. OTP sent to the provided phone number.'
                otp = randint(1000, 9999)
                my_session = SessionStore()
                my_session['phone'] = phone
                my_session['country_code'] = country_code
                my_session['email'] = request_data['email'] if 'email' in request_data else None
                my_session['full_name'] = request_data['full_name'] if 'full_name' in request_data else None
                my_session['dob'] = request_data['dob'] if 'dob' in request_data else None
                my_session['password'] = request_data['password']
                my_session['otp'] = otp
                my_session['otp_count'] = 5
                my_session.create()
                data['session_key'] = my_session.session_key
                send_phone_otp(phone,otp)
                my_session.save()
            else:
                data['status'] = 'error'
                data['message'] = 'phone number already exists !'
                status_code = status.HTTP_400_BAD_REQUEST
        else:
            data['status'] = 'error'
            data['message'] = 'User registration failed.'
            data['errors'] = serializer.errors
        return Response(data, status=status_code)
    else:
        return Response({}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def verify_phone(request):
    session_key = request.data.get('session_key')
    my_session = SessionStore(session_key=session_key)
    data = {}
    otp = int(request.data.get('otp'))
    if("otp" in my_session and "otp_count" in my_session) and otp == my_session['otp']  and (my_session['otp_count'] > 0):
        request_data = request.data.copy()
        request_data['country_code'] = my_session['country_code']
        request_data['phone'] = my_session['phone']
        request_data['password'] = my_session['password']
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            user = serializer.save()
            user.phone_verified=True
            user.save()
            data['response'] = 'successfully registered new user.'
            data['email'] = user.email
            data['pk'] = user.pk
            try:
                token = Token.objects.get(user=user).key
            except Token.DoesNotExist:
                token = Token.objects.create(user=user).key
            save_login_history(request,user,"registered with phone")
            my_session.delete()    
            data['token'] = token
            data['response'] = "Phone Number Verfied Successfully"
            status_code=status.HTTP_200_OK
        else:
            data = serializer.errors
            status_code=status.HTTP_400_BAD_REQUEST
        return Response(data,status=status_code)
    else:
        if("otp_count" in my_session and my_session['otp_count'] > 0):
            my_session['otp_count'] -= 1
            data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            data['error_message'] = "Limit Exceeded, Register again"

        status_code=status.HTTP_400_BAD_REQUEST
    return Response(data,status=status_code)
# >>>>> Register with phone number <<<<<<<<<
# >>>>> Register with phone number <<<<<<<<<



# >>>>> Register with email <<<<<<<<<
# >>>>> Register with email <<<<<<<<<
@api_view(['POST',])
@permission_classes((AllowAny, ))
# @authentication_classes([SessionAuthentication])
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def registration_email(request):
    status_code = status.HTTP_400_BAD_REQUEST
    if request.method == 'POST':
        data = {}
        email = request.data.get('email', '0')
        request_data = request.data.copy()
        request_data['password'] = request_data['password'] if 'password' in request_data else random_password(16)
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            status_code = status.HTTP_200_OK
            data = serializer.data
            if(validate_email(email)):
                data['status'] = 'success'
                data['message'] = 'User registration successful. OTP sent to the provided email address.'
                otp = randint(1000, 9999)
                my_session = SessionStore()
                my_session['email'] = email
                my_session['country_code'] = request_data['country_code'] if 'country_code' in request_data else None
                my_session['phone'] = request_data['phone'] if 'phone' in request_data else None
                my_session['full_name'] = request_data['full_name'] if 'full_name' in request_data else None
                my_session['dob'] = request_data['dob'] if 'dob' in request_data else None
                my_session['password'] = request_data['password']
                my_session['otp'] = otp
                my_session['otp_count'] = 5
                my_session.create()
                data['session_key'] = my_session.session_key
                send_email_otp(email,otp)
                my_session.save()
            else:
                data['status'] = 'error'
                data['message'] = 'Email address already exists !'
                status_code = status.HTTP_400_BAD_REQUEST
        else:
            data['status'] = 'error'
            data['message'] = 'User registration failed.'
            data['errors'] = serializer.errors
        return Response(data, status=status_code)
    else:
        return Response({}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def verify_email(request):
    session_key = request.data.get('session_key')
    my_session = SessionStore(session_key=session_key)
    data = {}
    otp = int(request.data.get('otp'))
    if("otp" in my_session and "otp_count" in my_session) and otp == my_session['otp']  and (my_session['otp_count'] > 0):
        request_data = request.data.copy()
        request_data['email'] = my_session['email']
        request_data['password'] = my_session['password']
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            user = serializer.save()
            user.email_verified=True
            user.save()
            data['response'] = 'successfully registered.....'
            data['email'] = user.email
            data['pk'] = user.pk

            try:
                token = Token.objects.get(user=user).key
            except Token.DoesNotExist:
                token = Token.objects.create(user=user).key
            save_login_history(request,user,"registered with email")            
            data['token'] = token
            data['response'] = "Email Verfied Successfully"
            status_code=status.HTTP_200_OK
        else:
            data = serializer.errors
            status_code=status.HTTP_400_BAD_REQUEST
        return Response(data,status=status_code)
    

    else:
        if("otp_count" in my_session and my_session['otp_count'] > 0):
            my_session['otp_count'] -= 1
            data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            data['error_message'] = "Limit Exceeded, Register again"

        status_code=status.HTTP_400_BAD_REQUEST
    return Response(data,status=status_code)
# >>>>> Register with email <<<<<<<<<
# >>>>> Register with email <<<<<<<<<


# >>>>> login with username and password <<<<<<<<<
# >>>>> login with username and password <<<<<<<<<         
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user_pass(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(request, username=username, password=password)
    if user:
        login(request, user)
        try:
            token = Token.objects.get(user=user).key
        except Token.DoesNotExist:
            token = Token.objects.create(user=user).key
        
        save_login_history(request,user,"username-pass login")
        
        
        response_data = {
            'token': token,
            'id': user.pk,
            'message': "Logged in successfully",
            'full_name': user.full_name,
            'username': user.username,
            }
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)        
# >>>>> login with username and password <<<<<<<<<
# >>>>> login with username and password <<<<<<<<<       


# >>>>> login with phone and password <<<<<<<<<
# >>>>> login with phone and password <<<<<<<<<
@api_view(['POST'])
@permission_classes([AllowAny])
def login_phone_pass(request):
    context = {}
    phone = request.data.get('phone')
    password = request.data.get('password')
    if(User.objects.filter(phone=phone, phone_verified=True).exists):
        user = User.objects.get(phone=phone, phone_verified=True)
        if user.check_password(password):
            try:
                token = Token.objects.get(user=user).key
            except Token.DoesNotExist:
                token = Token.objects.create(user=user).key

            save_login_history(request,user,"phone-pass login")
            
            response_data = {'user_id': user.pk, 'token': token}
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            context['error'] = 'Invalid password or Phone'
            return Response(context, status=status.HTTP_401_UNAUTHORIZED)
    else:
        context['error'] = 'User not found'
        return Response(context, status=status.HTTP_401_UNAUTHORIZED)
# >>>>> login with phone and password <<<<<<<<<
# >>>>> login with phone and password <<<<<<<<<


# >>>>> Login with email and password <<<<<<<<<
# >>>>> Login with email and password <<<<<<<<< 
@api_view(['POST',])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def login_email_pass(request):
    context = {}
    email = request.data.get('email')
    password = request.data.get('password')
    if(User.objects.filter(email=email, email_verified=True).exists):
        user = User.objects.get(email=email, email_verified=True)
        if user.check_password(password):
            try:
                token = Token.objects.get(user=user).key
            except Token.DoesNotExist:
                token = Token.objects.create(user=user).key
            save_login_history(request,user,"email-pass login")

            response_data = {'user_id': user.pk, 'token': token}
            return Response(response_data, status=status.HTTP_200_OK)
        
        else:
            context['error'] = 'Invalid password'
            return Response(context, status=status.HTTP_401_UNAUTHORIZED)
    else:
        context['error'] = 'User not found'
        return Response(context, status=status.HTTP_401_UNAUTHORIZED)
# >>>>> Login with email and password <<<<<<<<<
# >>>>> Login with email and password <<<<<<<<<


    
# >>>>> Login with phone and otp <<<<<<<<<
# >>>>> Login with phone and otp <<<<<<<<<
@api_view(['POST'])
@permission_classes([AllowAny])
def login_phone_otp(request):
    phone = request.data.get('phone')
    try:
        user = User.objects.get(phone=phone, phone_verified=True)
    except User.DoesNotExist:
        return Response({'error': 'User not found or phone not verified'}, status=status.HTTP_404_NOT_FOUND)
    
    otp = randint(1000, 9999)
    my_session = SessionStore()
    my_session['phone'] = phone
    my_session['pk'] = str(user.pk)
    my_session['otp'] = otp
    my_session['otp_count'] = 5  
    my_session.create()
    send_phone_otp(phone,otp)
    response_data = {
        'session_key': my_session.session_key,
        'message': 'OTP sent successfully'
        }
    return Response(response_data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser, FormParser, MultiPartParser, FileUploadParser])
def verify_login_phone_otp(request):
    otp = int(request.data.get('otp'))
    session_key = request.data.get('session_key')

    try:
        my_session = SessionStore(session_key=session_key)
    except Session.DoesNotExist:
        return Response({'detail': 'Invalid session key'}, status=status.HTTP_400_BAD_REQUEST)
    
    if("otp" in my_session and "otp_count" in my_session) and otp == my_session['otp']  and (my_session['otp_count'] > 0):
        user = User.objects.get(pk=my_session['pk'])
        try:
            token = Token.objects.get(user=user).key
        except Token.DoesNotExist:
            token = Token.objects.create(user=user).key
        save_login_history(request,user,"phone-otp login")
        
        response_data = {
            'token': token,
            'id': my_session['pk'],
            'message': "Logged in successfully",
            'full_name': user.full_name,
            'username': user.username,
            }
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        response_data = {}
        if("otp_count" in my_session and my_session['otp_count'] > 0):
            my_session['otp_count'] -= 1
            response_data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            response_data['error_message'] = "Limit Exceeded, Register again"
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
    
# >>>>> Login with phone and otp <<<<<<<<<
# >>>>> Login with phone and otp <<<<<<<<<


# >>>>> Login with email and otp <<<<<<<<<
# >>>>> Login with email and otp <<<<<<<<<
@api_view(['POST'])
@permission_classes([AllowAny])
def login_email_otp(request):
    email = request.data.get('email')
    try:
        user = User.objects.get(email=email, email_verified=True)
    except User.DoesNotExist:
        return Response({'error': 'User not found or Email not verified'}, status=status.HTTP_404_NOT_FOUND)
    otp = randint(1000, 9999)
    my_session = SessionStore()
    my_session['email'] = email
    my_session['pk'] = str(user.pk)
    my_session['otp'] = otp
    my_session['otp_count'] = 5  
    my_session.create()
    my_session.save()
    send_email_otp(email,otp)
    response_data = {
        'session_key': my_session.session_key,
        'message': 'OTP sent successfully'
    }
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def verify_login_email_otp(request):
    otp = int(request.data.get('otp'))
    session_key = request.data.get('session_key')
    try:
        my_session = SessionStore(session_key=session_key)
    except Session.DoesNotExist:
        return Response({'detail': 'Invalid session key'}, status=status.HTTP_400_BAD_REQUEST)

    if("otp" in my_session and "otp_count" in my_session) and otp == my_session['otp']  and (my_session['otp_count'] > 0):
        user_id = my_session['pk']
        user = User.objects.get(pk=user_id)
        try:
            token = Token.objects.get(user=user).key
        except Token.DoesNotExist:
            token = Token.objects.create(user=user).key
        save_login_history(request,user,"email-otp login")
        
        response_data = {
            'token': token,
            'id': my_session['pk'],
            'message': "Logged in successfully",
            'full_name': user.full_name,
            'username': user.username,
            }
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        response_data = {}
        if("otp_count" in my_session and my_session['otp_count'] > 0):
            my_session['otp_count'] -= 1
            response_data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            response_data['error_message'] = "Limit Exceeded, Register again"
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
# >>>>> Login with email and otp <<<<<<<<<
# >>>>> Login with email and otp <<<<<<<<<
    


@api_view(['POST',])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def logout_view(request):
    context = {}
    try:
        request.user.auth_token.delete()
        context['response'] = 'LogOut Successful.'
        status_code=status.HTTP_200_OK
    except:
        context['response'] = 'Error'
        context['error_message'] = 'Invalid Token'
        status_code=status.HTTP_400_BAD_REQUEST
    return Response(context,status=status_code)



@api_view(['POST'])
@permission_classes([AllowAny])
def forget_password_username(request):
    username=request.data.get('username')
    user=User.objects.get(username=username)
    if user:
        otp = randint(1000, 9999)
        my_session = SessionStore()
        my_session['username'] = username
        my_session['pk'] = str(user.pk)
        my_session['otp'] = otp
        my_session['otp_count'] = 5  
        my_session.create()
        my_session.save()
        if(user.phone_verified):
            send_phone_otp(user.country_code,user.phone,otp)
        if(user.email_verified):
            send_email_otp(user.email,otp)

        response_data = {
            'session_key': my_session.session_key,
            'message': 'OTP sent successfully'
            }
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'invalid cridential'},status=status.HTTP_400_BAD_REQUEST)  
    

@api_view(['POST'])
@permission_classes([AllowAny])
def forget_password_phone(request):
    phone=request.data.get('phone')
    user=User.objects.get(phone=phone,phone_verified=True)
    if user:
        otp = randint(1000, 9999)
        my_session = SessionStore()
        my_session['phone'] = phone
        my_session['pk'] = str(user.pk)
        my_session['otp'] = otp
        my_session['otp_count'] = 5  
        my_session.create()
        my_session.save()
        if(user.phone_verified):
            send_phone_otp(user.country_code,user.phone,otp)
        if(user.email_verified):
            send_email_otp(user.email,otp)

        response_data = {
            'session_key': my_session.session_key,
            'message': 'OTP sent successfully'
            }
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'invalid cridential'},status=status.HTTP_400_BAD_REQUEST)  
    


@api_view(['POST'])
@permission_classes([AllowAny])
def forget_password_email(request):
    email=request.data.get('email')
    user=User.objects.get(email=email,email_verified=True)
    if user:
        otp = randint(1000, 9999)
        my_session = SessionStore()
        my_session['email'] = email
        my_session['pk'] = str(user.pk)
        my_session['otp'] = otp
        my_session['otp_count'] = 5  
        my_session.create()
        my_session.save()
        if(user.phone_verified):
            send_phone_otp(user.country_code,user.phone,otp)
        if(user.email_verified):
            send_email_otp(user.email,otp)

        response_data = {
            'session_key': my_session.session_key,
            'message': 'OTP sent successfully'
            }
        return Response(response_data, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'invalid cridential'},status=status.HTTP_400_BAD_REQUEST)  
    


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_forget_password(request):
    if request.method == 'POST':
        session_key = request.data.get('session_key')
        try:
            my_session = SessionStore(session_key=session_key)
        except:
            return Response({'detail': 'Invalid session key'}, status=status.HTTP_400_BAD_REQUEST)
        
        otp = int(request.data.get('otp'))
        if("otp" in my_session and "otp_count" in my_session) and otp == my_session['otp']  and (my_session['otp_count'] > 0):
            serializer = PasswordResetSerializer(data=request.data)
            if serializer.is_valid():
                user = User.objects.get(pk=my_session['pk'])
                new_password = serializer.validated_data['new_password']
                user.set_password(new_password)
                user.save()
                my_session.delete()
                try:
                    token = Token.objects.get(user=user).key
                except Token.DoesNotExist:
                    token = Token.objects.create(user=user).key
                save_login_history(request,user,"forget password")

                response_data = {
                    'message': 'Password reset successfully.',
                    'token':token
                    }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            response_data = {}
            if("otp_count" in my_session and my_session['otp_count'] > 0):
                my_session['otp_count'] -= 1
                response_data['error_message'] = "invalid OTP"
            else:
                my_session.delete()
                response_data['error_message'] = "Limit Exceeded, Register again"
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
    return Response({'message': 'Invalid request method.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    if request.method == 'POST':

        old_password = request.data.get('password')
        new_password = request.data.get('new_password')
        user = request.user
        if user.check_password(old_password):
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password Change successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'invalid Password'},status=status.HTTP_400_BAD_REQUEST)
            
    return Response({'message': 'Invalid request method.'}, status=status.HTTP_400_BAD_REQUEST)





# >>>>> Phone verification <<<<<<<<<
# >>>>> Phone verification <<<<<<<<<
@api_view(['POST',])
@permission_classes((IsAuthenticated, ))
# @authentication_classes([SessionAuthentication])
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def phone_verification_otp(request):
    status_code = status.HTTP_400_BAD_REQUEST
    if request.method == 'POST':
        data = {}
        user = request.user
        phone = request.user.phone
        country_code = request.user.country_code
        if(phone and user.phone_verified == False):
            otp = randint(1000, 9999)
            my_session = SessionStore()
            my_session['otp'] = otp
            my_session['otp_count'] = 5
            my_session.create()
            data['session_key'] = my_session.session_key
            data['message'] = "OTP sent"
            send_phone_otp(country_code,phone,otp)
            my_session.save()
            status_code = status.HTTP_200_OK
        else:
            data['status'] = 'error'
            data['message'] = 'Somthing went wrong..!'
        return Response(data, status=status_code)
    else:
        return Response({}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def verify_phone_verification_otp(request):
    session_key = request.data.get('session_key')
    my_session = SessionStore(session_key=session_key)
    data = {}
    otp = int(request.data.get('otp'))
    user = request.user
    if("otp" in my_session and "otp_count" in my_session) and otp == my_session['otp']  and (my_session['otp_count'] > 0):
        user.phone_verified=True
        user.save()
        data['phone'] = user.phone
        data['pk'] = user.pk
        data['response'] = "Phone number Verfied Successfully"
        status_code=status.HTTP_200_OK
        my_session.delete()
    else:
        if("otp_count" in my_session and my_session['otp_count'] > 0):
            my_session['otp_count'] -= 1
            data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            data['error_message'] = "Limit Exceeded, Register again"

        status_code=status.HTTP_400_BAD_REQUEST
    return Response(data,status=status_code)
    
# >>>>> Phone verification <<<<<<<<<
# >>>>> Phone verification <<<<<<<<<


# >>>>> Email verification <<<<<<<<<
# >>>>> Email verification <<<<<<<<<
@api_view(['POST',])
@permission_classes((IsAuthenticated, ))
# @authentication_classes([SessionAuthentication])
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def email_verification_otp(request):
    status_code = status.HTTP_400_BAD_REQUEST
    if request.method == 'POST':
        data = {}
        user = request.user
        email = request.user.email
        if(email and user.email_verified == False):
            otp = randint(1000, 9999)
            my_session = SessionStore()
            my_session['otp'] = otp
            my_session['otp_count'] = 5

            my_session.create()
            data['session_key'] = my_session.session_key
            data['message'] = "OTP sent"
            send_email_otp(email,otp)
            my_session.save()
            status_code = status.HTTP_200_OK
        else:
            data['status'] = 'error'
            data['message'] = 'Somthing went wrong..!'
        return Response(data, status=status_code)
    else:
        return Response({}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def verify_email_verification_otp(request):
    session_key = request.data.get('session_key')
    my_session = SessionStore(session_key=session_key)
    data = {}
    otp = int(request.data.get('otp'))
    user = request.user
    if("otp" in my_session and "otp_count" in my_session) and otp == my_session['otp']  and (my_session['otp_count'] > 0):
        user.email_verified=True
        user.save()
        data['email'] = user.email
        data['pk'] = user.pk
        data['response'] = "Email Verfied Successfully"
        status_code=status.HTTP_200_OK
        my_session.delete()
    else:
        if("otp_count" in my_session and my_session['otp_count'] > 0):
            my_session['otp_count'] -= 1
            data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            data['error_message'] = "Limit Exceeded, Register again"

        status_code=status.HTTP_400_BAD_REQUEST
    return Response(data,status=status_code)
    
# >>>>> Email verification <<<<<<<<<
# >>>>> Email verification <<<<<<<<<






class LoginHistoryViewSet(ModelViewSet):
    permission_classes = [IsAdmin]
    queryset =LoginHistory.objects.all()
    serializer_class = LoginHistorySerializer
    filter_backends = [SearchFilter]
    search_fields = ['user__username','user__phone','user__email','user__full_name','ip_address']

    # def get_permissions(self):
    #     if self.action == 'retrieve':
    #         permission_classes = [IsFieldstaff]
    #     else:
    #         permission_classes = [IsAdmin]
    #     return [permission() for permission in permission_classes]