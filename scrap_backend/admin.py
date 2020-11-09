from django.contrib import admin
from .models import User, Refresh_Token, Product_Id, Failure_Cause, Scrap, Cache_Token
# Register your models here.
admin.site.register(User)
admin.site.register(Refresh_Token)
admin.site.register(Failure_Cause)
admin.site.register(Scrap)
admin.site.register(Cache_Token)
admin.site.register(Product_Id)