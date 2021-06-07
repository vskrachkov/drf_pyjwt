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
DRF_PYJWT_JWKS_URI = "https://api.sample/jwks.json"
DRF_PYJWT_ALGORITHMS = ["RS256"]
DRF_PYJWT_KWARGS = {"audience": "https://api.sample"}
```

In `views.py` add `PyJWTAuthentication` class to authentication classes.

``` 
@api_view(["get"])
@authentication_classes([PyJWTAuthentication])
@permission_classes([])
def example(request: Request) -> Response:
    return Response({"some": "response"})
```

# Settings Reference
### DRF_PYJWT_JWKS_URI
Required: `True`

Type: `str`

### DRF_PYJWT_ALGORITHMS
Required: `False`

Type: `List[str]`

Default: `["RS256"]`

Value which will be passed as `algorithms` argument to [pyjwt.jwt.decode](https://pyjwt.readthedocs.io/en/stable/api.html?highlight=decode#jwt.decode) function.

### DRF_PYJWT_OPTIONS
Required: `False`
Type: `dict`

Value which will be passed as `options` argument to [pyjwt.jwt.decode](https://pyjwt.readthedocs.io/en/stable/api.html?highlight=decode#jwt.decode) function.

### DRF_PYJWT_KWARGS
Required: `False`
Type: `dict`

Value which will be passed as `**kwargs` argument to [pyjwt.jwt.decode](https://pyjwt.readthedocs.io/en/stable/api.html?highlight=decode#jwt.decode) function.

### DRF_PYJWT_LOOKUP_USER
Required: `False`
Type: `str`

Import path to the `Callable[[dict], Optional[AbstractBaseUser]]`
