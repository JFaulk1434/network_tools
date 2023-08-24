from django.shortcuts import render
from django.http import HttpResponse

from .forms import PortScanForm
from .portscan_util import port_scan


def index(request):
    if request.method == "POST":
        form = PortScanForm(request.POST)
        if form.is_valid():
            ip_address = form.cleaned_data.get("ip_address")
            min_port = form.cleaned_data.get("min_port")
            max_port = form.cleaned_data.get("max_port")
            open_ports = port_scan(ip_address, min_port, max_port)
            return render(
                request, "portscan/index.html", {"form": form, "open_ports": open_ports}
            )
    else:
        form = PortScanForm()

    return render(request, "portscan/index.html", {"form": form})
