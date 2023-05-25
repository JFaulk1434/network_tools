from django import forms


class NetScanForm(forms.Form):
    ip_address = forms.GenericIPAddressField(protocol="IPv4")
    subnet = forms.IntegerField(initial=24, min_value=0, max_value=32)
