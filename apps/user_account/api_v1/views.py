from django.contrib.auth import get_user_model
from rest_framework import status
from random import randint
from rest_framework import viewsets
from apps.user_account.models import User ,LoginHistory

from rest_framework.decorators import action
from django.contrib.auth import authenticate, login
from rest_framework.permissions import AllowAny,IsAuthenticated
from apps.user_account.functions import validate_email,validate_username,IsAdmin
from rest_framework.authentication import SessionAuthentication
from django.contrib.sessions.models import Session
from django.http import HttpResponseBadRequest
from rest_framework.viewsets import  ModelViewSet
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, UpdateModelMixin 
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
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
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.filters import SearchFilter

User = get_user_model()

from rest_framework.generics import (
    # ListAPIView,
    RetrieveUpdateAPIView,
    # RetrieveUpdateDestroyAPIView,
)
class UserViewSet(RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet):
    permission_classes = [IsAdmin]

    serializer_class = UserSerializer
    queryset = User.objects.all()
    lookup_field = "username"

    
    # def get_permissions(self):
    #     if self.action in ['destroy', 'update']:
    #         permission_classes = [IsAdmin]
    #     else:
    #         permission_classes = [IsAuthenticated]
    #     return [permission() for permission in permission_classes]


    def get_queryset(self, *args, **kwargs):
        assert isinstance(self.request.user.id, int)
        return self.queryset.filter(id=self.request.user.id)

    @action(detail=False)
    def me(self, request):
        serializer = UserSerializer(request.user, context={"request": request})
        return Response(status=status.HTTP_200_OK, data=serializer.data)
    
    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     self.perform_create(serializer)
    #     headers = self.get_success_headers(serializer.data)
    #     return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save()


# class UserLogIn(ObtainAuthToken):

#     def post(self, request, *args, **kwargs):
#         serializer = self.serializer_class(data=request.data,
#                                            context={'request': request})
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data['user']       
#         token = Token.objects.get(user=user)
#         return Response({
#             'token': token.key,
#             'id': user.pk,
#             'username': user.username
#         })


# class UserProfile(RetrieveUpdateAPIView):
#     """
#     get:
#         Returns the profile of user.

#     put:
#         Update the detail of a user instance

#         parameters: [first_name, last_name,]
#     """

#     serializer_class = UsersListSerializer
#     permission_classes = [
#         IsAuthenticated,
#     ]

#     def get_object(self):
#         return self.request.user
    








# @csrf_exempt
@api_view(['POST',])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def registration_view(request):
    status_code=status.HTTP_400_BAD_REQUEST
    if request.method == 'POST':
        data = {}
        email = request.data.get('email', '0').lower() 
        if validate_email(email) != None:
            data['error_message'] = 'That email is already in use.'
            data['response'] = 'Error'
            return Response(data)

        username = request.data.get('username', '0')
        if validate_username(username) != None:
            data['error_message'] = 'That username is already in use.'
            data['response'] = 'Error'  
            return Response(data)
        request_data = request.data.copy()
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            account = serializer.save()
            data['response'] = 'successfully registered new user.'
            data['email'] = account.email
            account.email_verified=True

            account.phone_verified=True
            account.is_admin=True
            account.is_superuser=True
            account.save()
            data['username'] = account.username
            try:
                token = Token.objects.get(user=account).key
            except Token.DoesNotExist:
                token = Token.objects.create(user=account).key
            data['token'] = token
            status_code=status.HTTP_200_OK
        else:
            data = serializer.errors
        return Response(data,status=status_code)


@csrf_exempt
@api_view(['POST',])
@permission_classes((AllowAny, ))
@authentication_classes([SessionAuthentication])
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def registration_phone(request):
    status_code=status.HTTP_400_BAD_REQUEST
    if request.method == 'POST':
        data = {}
        username = request.data.get('username', '0')
        phone = request.data.get('phone', '0')      
        if validate_username(username) != None:
            data['error_message'] = 'That username is already in use.'
            data['response'] = 'Error'
            return Response(data)
        request_data = request.data.copy()
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            status_code=status.HTTP_200_OK
            data= serializer.data
            otp = randint(1000,9999)
            print(otp)
            my_session = SessionStore()
            my_session['phone'] = phone
            my_session['password'] = request.data.get('password')
            my_session['otp'] = otp
            my_session['login_otp_count'] = 5
            my_session.create()
            data['session_key'] = my_session.session_key
            my_session.save()
            print(my_session['otp'])
        else:
            data = serializer.errors
            status_code=status.HTTP_400_BAD_REQUEST
            return Response(data,status=status_code)
        

@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def verify_phone(request):

    session_key = request.data.get('session_key')
    my_session = SessionStore(session_key=session_key)
    data = {}
    otp = int(request.data.get('otp'))
    otp_verification = my_session['otp']
    if ((int(otp) == int(otp_verification))and (my_session['login_otp_count'] > 0)):

        request_data = request.data.copy()
        request_data['phone'] = my_session['phone']
        request_data['password'] = my_session['password']
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            user = serializer.save()
            user.phone_verified=True
            data['response'] = 'successfully registered new user.'
            data['email'] = user.email
            data['pk'] = user.pk

            try:
                token = Token.objects.get(user=user).key
            except Token.DoesNotExist:
                token = Token.objects.create(user=user).key
                
            data['token'] = token
            data['response'] = "Phone Number Verfied Successfully"
            status_code=status.HTTP_200_OK
        else:
            data = serializer.errors
            status_code=status.HTTP_400_BAD_REQUEST
        return Response(data,status=status_code)
    

    else:
        if(my_session['login_otp_count'] > 0):
            my_session['login_otp_count'] -= 1
            data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            data['error_message'] = "Limit Exceeded, Register again"

        status_code=status.HTTP_400_BAD_REQUEST
    return Response(data,status=status_code)



@csrf_exempt
@api_view(['POST',])
@permission_classes((AllowAny, ))
@authentication_classes([SessionAuthentication])
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def registration_email(request):
    status_code=status.HTTP_400_BAD_REQUEST
    if request.method == 'POST':
        data = {}
        email = request.data.get('email', '0')
        username=request.data.get('username' ,'0')
        if validate_email(email) != None:
            data['error_message'] = 'That email is already in use.'
            data['response'] = 'Error'    
            return Response(data)
        if validate_username(username) != None:
            data['error_message'] = 'That username is already in use.'
            data['response'] = 'Error'
            return Response(data)
        
        request_data = request.data.copy()
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            status_code=status.HTTP_200_OK
            data= serializer.data
            otp = randint(1000,9999)
            print(otp)
            my_session = SessionStore()
            my_session['email'] = email
            my_session['username'] = username
            my_session['password'] = request.data.get('password')
            my_session['otp'] = otp
            my_session['login_otp_count'] = 5
            my_session.create()
            data['session_key'] = my_session.session_key
            my_session.save()
            print(my_session['otp'])
        else:
            data = serializer.errors
            status_code=status.HTTP_400_BAD_REQUEST
            return Response(data,status=status_code)

@api_view(['POST'])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def verify_email(request):

    session_key = request.data.get('session_key')
    my_session = SessionStore(session_key=session_key)
    data = {}
    otp = int(request.data.get('otp'))
    otp_verification = my_session['otp']
    if ((int(otp) == int(otp_verification))and (my_session['login_otp_count'] > 0)):

        request_data = request.data.copy()
        request_data['email'] = my_session['email']
        request_data['username'] = my_session['username']
        request_data['password'] = my_session['password']
        serializer = UserSerializer(data=request_data)
        if serializer.is_valid():
            user = serializer.save()
            user.email_verified=True
            data['response'] = 'successfully registered.....'
            data['email'] = user.email
            data['pk'] = user.pk

            try:
                token = Token.objects.get(user=user).key
            except Token.DoesNotExist:
                token = Token.objects.create(user=user).key
                
            data['token'] = token
            data['response'] = "Email Verfied Successfully"
            status_code=status.HTTP_200_OK
        else:
            data = serializer.errors
            status_code=status.HTTP_400_BAD_REQUEST
        return Response(data,status=status_code)
    

    else:
        if(my_session['login_otp_count'] > 0):
            my_session['login_otp_count'] -= 1
            data['error_message'] = "invalid OTP"
        else:
            my_session.delete()
            data['error_message'] = "Limit Exceeded, Register again"

        status_code=status.HTTP_400_BAD_REQUEST
    return Response(data,status=status_code)


            
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    print(password)

    user = authenticate(request, username=username, password=password)

    if user:
        login(request, user)
        serializer = UserSerializer(user)
        return Response(serializer.data)
    else:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)        
    
@api_view(['POST'])
@permission_classes([AllowAny])
def login_phone(request):
    context = {}
    phone = request.data.get('phone')
    password = request.data.get('password')

    account = User.objects.get(phone=phone, phone_verified=True)
        
    if account.check_password(password):
        try:
            token = Token.objects.get(user=account).key
        except Token.DoesNotExist:
            token = Token.objects.create(user=account).key

        response_data = {'user_id': account.pk, 'token': token}
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    
    else:
        context['error'] = 'Invalid password or Phone'
        return Response(context, status=status.HTTP_401_UNAUTHORIZED)


    
@api_view(['POST',])
@permission_classes((AllowAny, ))
@parser_classes([JSONParser,FormParser, MultiPartParser,FileUploadParser])
def login_email(request):

    context = {}
    email = request.data.get('email')
    password = request.data.get('password')

    account = User.objects.get(email=email, email_verified=True)
        
    if account.check_password(password):
        try:
            token = Token.objects.get(user=account).key
        except Token.DoesNotExist:
            token = Token.objects.create(user=account).key

        response_data = {'user_id': account.pk, 'token': token}
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    
    else:
        context['error'] = 'Invalid password'
        return Response(context, status=status.HTTP_401_UNAUTHORIZED)



    

@api_view(['POST'])
@permission_classes([AllowAny])
def login_phone_otp(request):
    data = {}
    phone = request.data.get('phone')

    try:
        account = User.objects.get(phone=phone, phone_verified=True)
    except User.DoesNotExist:
        return Response({'error': 'User not found or phone not verified'}, status=status.HTTP_404_NOT_FOUND)

    otp = randint(1000, 9999)
    my_session = SessionStore()
    my_session['phone'] = phone
    my_session['pk'] = str(account.pk)
    my_session['otp'] = otp
    my_session['login_otp_count'] = 5  
    my_session.create()

    print(otp)
    return Response({'session_key': my_session.session_key, 'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

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
    print(otp)
    
    stored_otp= my_session['otp']
    print(stored_otp)
    if otp == stored_otp:
        user_id = my_session['pk']
        user = User.objects.get(pk=user_id)
        try:
            token = Token.objects.get(user=user).key
        except Token.DoesNotExist:
            token = Token.objects.create(user=user).key

        return Response({'token': token, 'user_id': user_id}, status=status.HTTP_200_OK)
    else:
        return Response({'detail': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@permission_classes([AllowAny])
def login_email_otp(request):
    data = {}
    email = request.data.get('email')
    # password = request.data.get('password')

    try:
        account = User.objects.get(email=email, email_verified=True)
    except User.DoesNotExist:
        return Response({'error': 'User not found or Email not verified'}, status=status.HTTP_404_NOT_FOUND)

    otp = randint(1000, 9999)
    my_session = SessionStore()
    my_session['email'] = email
    my_session['pk'] = str(account.pk)
    my_session['otp'] = otp
    my_session['login_otp_count'] = 5  
    my_session.create()
    my_session.save()

    print(otp)
    # data= my_session.session_key
    return Response({'session_key': my_session.session_key, 'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

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
    print(otp)
    
    stored_otp= my_session['otp']
    print(stored_otp)
    if otp == stored_otp:
        user_id = my_session['pk']
        user = User.objects.get(pk=user_id)
        try:
            token = Token.objects.get(user=user).key
        except Token.DoesNotExist:
            token = Token.objects.create(user=user).key

        return Response({'token': token, 'user_id': user_id}, status=status.HTTP_200_OK)
    else:
        return Response({'detail': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)




    # if otp == stored_otp:

    #     user_id = my_session['pk']
    #     user = User.objects.get(pk=user_id)
    #     try:
    #         token = Token.objects.get(user=user).key
    #         return Response({'token': token, 'user_id': user_id}, status=status.HTTP_200_OK)
    #     except Token.DoesNotExist:
    #         token = Token.objects.create(user=user).key

    #         return Response({'token': token, 'user_id': user_id}, status=status.HTTP_200_OK)
    # else:
    #     return Response({'detail': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


# @api_view(['PUT',])
# @permission_classes((AllowAny, ))
# def update_account_view(request):
#     data={}
    
#     if request.method == 'PUT':
#         user = request.user
#         serializer = AccountPropertiesSerializer(user, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({'response': 'Account update success'}, status=status.HTTP_200_OK)
#     else:

#         data = {
#             'response': 'Error',
#             'error_message': 'Data Not Valid',
#             'errors': serializer.errors,
#             }    
#         return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
#     return Response({'response': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
  

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
def forget_password(request):
    email=request.data.get('email')
    user=User.objects.get(email=email)
    if user:
        otp = randint(1000, 9999)
        my_session = SessionStore()
        my_session['email'] = email
        my_session['pk'] = str(user.pk)
        my_session['otp'] = otp
        my_session['login_otp_count'] = 5  
        my_session.create()
        my_session.save()

        print(otp)
        # data= my_session.session_key
        return Response({'session_key': my_session.session_key, 'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'invalid cridential'},status=status.HTTP_400_BAD_REQUEST)  
    
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset(request):
    if request.method == 'POST':
        otp = int(request.data.get('otp'))
        session_key = request.data.get('session_key')

        try:
            my_session = SessionStore(session_key=session_key)
        except Session.DoesNotExist:
            return Response({'detail': 'Invalid session key'}, status=status.HTTP_400_BAD_REQUEST)
        print(otp)
    
        stored_otp= my_session['otp']
        print(stored_otp)
        if otp == stored_otp:

            serializer = PasswordResetSerializer(data=request.data)

            if serializer.is_valid():
                user_id = my_session['pk']

                user = User.objects.get(pk=user_id)
                new_password = serializer.validated_data['new_password']

                user.set_password(new_password)
                user.save()

                return Response({'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    return Response({'message': 'Invalid request method.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def change_password(request):
    if request.method == 'POST':
        email=request.data.get('email')
        old_password = request.data.get('password')
        new_password= request.data.get('new_password')

        account = User.objects.get(email=email, email_verified=True)
        if account.check_password(old_password):
            account.set_password(new_password)
            account.save()
            return Response({'message': 'Password Change successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'invalid Password'},status=status.HTTP_400_BAD_REQUEST)
            
    return Response({'message': 'Invalid request method.'}, status=status.HTTP_400_BAD_REQUEST)






class LoginHistoryViewSet(ModelViewSet):
    permission_classes = [AllowAny]
    queryset =LoginHistory.objects.all()
    serializer_class = LoginHistorySerializer
    filter_backends = [SearchFilter]
    search_fields = ['username']

    # def get_permissions(self):
    #     if self.action == 'retrieve':
    #         permission_classes = [IsFieldstaff]
    #     else:
    #         permission_classes = [IsAdmin]
    #     return [permission() for permission in permission_classes]