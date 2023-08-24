from django.urls import path

from . import views

app_name = "bandwidth"
urlpatterns = [
    path("", views.index, name="index"),
]
