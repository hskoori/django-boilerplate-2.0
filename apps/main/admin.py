from django.contrib import admin
from .models import *


# Register your models here.
class CronjobCallAdmin(admin.ModelAdmin):
    list_display = ('id',
    'date_added',
    'title' ,
    )
admin.site.register(CronjobCall,CronjobCallAdmin)


