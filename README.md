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
def example(request: Request) -> Response:
    token: dict = request.auth
    print("Access token: {token}")
    return Response({"some": "response"})
```

By default `PyJWTAuthentication` cannot lookup user by token, that's why you will get `None` in `request.user`. 
You can provide lookup user function using `DRF_PYJWT_LOOKUP_USER` setting. 
After this `PyJWTAuthentication` will populate `request.user` using provided function.

# Settings Reference
### DRF_PYJWT_JWKS_URI
Required: `True`

Type: `str`

Value which will be passed as `uri` argument to [jwt.jwks_client.PyJWKClient]() function 

### DRF_PYJWT_ALGORITHMS
Required: `False`

Type: `List[str]`

Default: `["RS256"]`

Example: `DRF_PYJWT_ALGORITHMS = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"`

Value which will be passed as `algorithms` argument to [jwt.decode](https://pyjwt.readthedocs.io/en/stable/api.html?highlight=decode#jwt.decode) function.

### DRF_PYJWT_OPTIONS
Required: `False`

Type: `dict`

Example: `DRF_PYJWT_OPTIONS = {"verify_exp": False}`

Value which will be passed as `options` argument to [jwt.decode](https://pyjwt.readthedocs.io/en/stable/api.html?highlight=decode#jwt.decode) function.

### DRF_PYJWT_KWARGS
Required: `False`

Type: `dict`

Example: `DRF_PYJWT_KWARGS = {"audience": "https://app.domain"}`

Value which will be passed as `**kwargs` argument to [jwt.decode](https://pyjwt.readthedocs.io/en/stable/api.html?highlight=decode#jwt.decode) function.

### DRF_PYJWT_LOOKUP_USER
Required: `False`

Type: `str` (Import path to the `Callable[[dict], Optional[AbstractBaseUser]]`)

Example:
```
def lookup_user(token: dict) -> Optional[AbstractBaseUser]:
    user_id = token["custom_claim_user_id"]
    user = User.objects.filter(pk=user_id).first()
    return user
```
