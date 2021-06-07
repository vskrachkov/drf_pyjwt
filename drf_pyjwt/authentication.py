import logging
from typing import Tuple, Any, Optional, Callable, ClassVar, TypeVar, cast, Dict

import jwt
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.module_loading import import_string
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

log = logging.getLogger(__name__)

_T = TypeVar("_T")


class PyJWTAuthentication(TokenAuthentication):
    keyword = "Bearer"

    _jwks_client: ClassVar[Optional[jwt.PyJWKClient]] = None

    @staticmethod
    def get_setting(name: str, default: _T) -> _T:
        return getattr(settings, name, default)

    @classmethod
    def get_jwks_client(cls) -> jwt.PyJWKClient:
        if not cls._jwks_client:
            cls._jwks_client = jwt.PyJWKClient(
                cls.get_setting("DRF_PYJWT_JWKS_URI", "")
            )
        return cls._jwks_client

    @classmethod
    def clear_jwks_cache(cls) -> None:
        cls._jwks_client = None

    def authenticate_credentials(self, key: str) -> Tuple[Any, dict]:
        try:
            token: dict = self.decode_token(key)
        except jwt.exceptions.PyJWTError as exc:
            log.info(f"Token decode error: {exc}")
            raise AuthenticationFailed("Invalid token")

        return (self.lookup_user(token), token)

    def decode_token(self, token: str) -> dict:
        signing_key = self.get_jwks_client().get_signing_key_from_jwt(token)
        return jwt.decode(
            jwt=token,
            key=signing_key.key,
            algorithms=self.get_setting("DRF_PYJWT_ALGORITHMS", ["RS256"]),
            options=self.get_setting("DRF_PYJWT_OPTIONS", {}),
            **cast(Dict[str, Any], self.get_setting("DRF_PYJWT_KWARGS", {})),
        )

    @classmethod
    def lookup_user(cls, token: dict) -> Optional[AbstractBaseUser]:
        if import_str := cls.get_setting("DRF_PYJWT_LOOKUP_USER", ""):
            _lookup_user: Callable[[dict], Optional[AbstractBaseUser]]
            _lookup_user = import_string(import_str)
            return _lookup_user(token)
        return None
