# drf_pyjwt
A JSON Web Token authentication extension for the Django REST Framework

[![PyPI Version][pypi-image]][pypi-url]
[![Maintainability](https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/maintainability)](https://codeclimate.com/github/vskrachkov/drf_pyjwt/maintainability)

[pypi-image]: https://img.shields.io/pypi/v/drf_pyjwt
[pypi-url]: https://pypi.org/project/drf_pyjwt/


# Installation

Using pip

`pip install drf_pyjwt`

Using pipenv

`pipenv install drf_pyjwt`

# Quick start
In your project’s `settings.py` add these settings.

```
DRF_PYJWT = {
    "JWKS_URI": "https://api.sample/jwks.json",
    "ALGORITHMS": ["RS256"],
    "KWARGS": {"audience": "https://api.sample"},
}
```

In `views.py` add `PyJWTAuthentication` class to authentication classes.

``` 
@api_view(["get"])
@authentication_classes([PyJWTAuthentication])
@permission_classes([])
def example(request: Request) -> Response:
    return Response({"some": "response"})
```