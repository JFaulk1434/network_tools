from django import forms


class PortScanForm(forms.Form):
    ip_address = forms.GenericIPAddressField(protocol="IPv4")
    min_port = forms.IntegerField(initial=1, min_value=1, max_value=65535)
    max_port = forms.IntegerField(initial=100, min_value=1, max_value=65535)
