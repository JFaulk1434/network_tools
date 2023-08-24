from django.shortcuts import render
from django.views.decorators.http import require_POST
from .forms import NetScanForm
from .netscan_util import netscan


# @require_POST
def index(request):
    form = NetScanForm(request.POST)
    if form.is_valid():
        ip_address = form.cleaned_data.get("ip_address")
        subnet = form.cleaned_data.get("subnet")
        devices = netscan(ip=ip_address, subnet=subnet)
        return render(request, "netscan/index.html", {"form": form, "devices": devices})
    else:
        form = NetScanForm()
    return render(request, "netscan/index.html", {"form": form})
