from mahall.models import MahallGroupAdmin, MahallUser
from rest_framework import permissions
from django.contrib.auth.models import Group




# from django.contrib.auth.decorators import user_passes_test

# def group_required(*group_names):
#     def in_groups(u):
#         if u.is_authenticated():
#             if bool(u.groups.filter(name__in=group_names)) | u.is_superuser:
#                 return True
#         return False
#     return user_passes_test(in_groups)


# class IsAdminlManager(permissions.BasePermission):
#     def has_permission(self, request, view):
#         if request.user.is_authenticated:
#             if  request.user.role in ['admin'] :
#                 return True
#         return False

# class IsAdmin(permissions.BasePermission):
#     def has_permission(self, request, view):
#         if request.user.is_authenticated:
#             if request.user.groups.filter(name='admin').exists():
#                 return True
#         return False

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            request_role = request.headers["Role"]
            if request.user.groups.all().exists() and request_role=="admin":
                return True
        return False

class IsMahallGroupAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            request_role = request.headers["Role"]
            if request.user.groups.all().exists() and request_role=="admin":
                return True
            elif MahallGroupAdmin.objects.filter(account =request.user).exists() and request_role=="group_admin":
                return True
        return False




# class IsQualityChecker(permissions.BasePermission):

#     def has_permission(self, request, view):
#         if request.user.is_authenticated:
#             if  request.user.role in ['admin', 'generalmanager', 'productionmanager' , 'qualitychecker'] :
#                 return True
#         return False

# 