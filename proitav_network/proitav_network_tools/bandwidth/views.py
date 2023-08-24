from django.shortcuts import render
from django.http import HttpResponse
from .bandwidth_util import bandwidth_test


def index(request):
    if request.method == "POST":
        context = bandwidth_test()
    else:
        context = {}

    return render(request, "bandwidth/index.html", context)
