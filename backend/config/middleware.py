"""
CipherVault custom middleware.

HideServerHeaderMiddleware strips the Server: header from every response,
so error pages and API responses don't reveal "wsgiserver cpython/3.15.0"
or any equivalent. Low-severity defence-in-depth.
"""
from django.utils.deprecation import MiddlewareMixin


class HideServerHeaderMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        # Some WSGI servers set this; strip it. The header isn't used by
        # any client of this API.
        if "Server" in response:
            del response["Server"]
        response["Server"] = "CipherVault"
        return response
