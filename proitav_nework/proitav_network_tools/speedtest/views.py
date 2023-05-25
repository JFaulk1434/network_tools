from django.shortcuts import render
from django.http import HttpResponse
from .speedtest_util import bandwidth_test


def index(request):
    # Call your bandwidth_test function to get the results
    results = bandwidth_test(request)

    # Render the results in a template and return as an HTTP response
    return render(request, "speedtest/index.html", {"results": results})
