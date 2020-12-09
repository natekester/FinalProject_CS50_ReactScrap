from django.contrib import admin
from .models import User, RefreshToken, ProductId, FailureCause, Scrap, CacheToken
# Register your models here.
admin.site.register(User)
admin.site.register(RefreshToken)
admin.site.register(FailureCause)
admin.site.register(Scrap)
admin.site.register(CacheToken)
admin.site.register(ProductId)
