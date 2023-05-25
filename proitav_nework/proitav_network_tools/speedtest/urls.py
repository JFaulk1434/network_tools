from django.urls import path

from . import views

app_name = "speedtest"
urlpatterns = [
    path("", views.index, name="index"),
]
