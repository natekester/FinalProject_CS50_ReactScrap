
from django.urls import include, path

urlpatterns = [
    
    path("", include("scrap_backend.urls"))

]