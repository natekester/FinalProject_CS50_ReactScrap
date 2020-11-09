"""finalProject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from . import views
from django.contrib import admin

#TODO: get rid of api's that might be compromising for production.

urlpatterns = [
    path("admin/", admin.site.urls),
    #path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    #path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('api/open_scrap/', views.open_scrap),
    path('api/closed_scrap/', views.closed_scrap),
    path('api/graph_data/', views.graph_data),
    path('api/create_user/', views.create_user, name='create_user'),#should remove and only use super user to create after testing.
    path('api/get_token/', views.get_token),
    path('api/check_token/', views.check_token),
    path('api/login/', views.login), #i.e. get refresh token.
    path('api/logout/', views.logout), #i.e. get refresh token.

    path('api/check_refresh_token/', views.check_refresh_token)
    

]
