import logging
from typing import Tuple, Any, Optional, Callable, ClassVar

import jwt
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.module_loading import import_string
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

log = logging.getLogger(__name__)


class PyJWTAuthentication(TokenAuthentication):
    keyword = "Bearer"

    _jwks_client: ClassVar[Optional[jwt.PyJWKClient]] = None

    @classmethod
    def get_jwks_client(cls) -> jwt.PyJWKClient:
        if not cls._jwks_client:
            cls._jwks_client = jwt.PyJWKClient(settings.DRF_PYJWT["JWKS_URI"])
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
            algorithms=self.get_algorithms(),
            options=self.get_options(),
            **self.get_kwargs(),
        )

    @staticmethod
    def lookup_user(token: dict) -> Optional[AbstractBaseUser]:
        if import_str := settings.DRF_PYJWT.get("LOOKUP_USER"):
            _lookup_user: Callable[[dict], Optional[AbstractBaseUser]]
            _lookup_user = import_string(import_str)
            return _lookup_user(token)
        return None

    @staticmethod
    def get_algorithms() -> Optional[list[str]]:
        return settings.DRF_PYJWT.get("ALGORITHMS")

    @staticmethod
    def get_options() -> Optional[dict]:
        return settings.DRF_PYJWT.get("OPTIONS")

    @staticmethod
    def get_kwargs() -> dict:
        return settings.DRF_PYJWT.get("KWARGS") or {}
