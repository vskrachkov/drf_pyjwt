import logging
from typing import Tuple, Any, Optional

import jwt.exceptions
from django.conf import settings
from jwt import PyJWKClient, decode
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

log = logging.getLogger(__name__)


class StubUser:
    is_authenticated = True


class PyJWTAuthentication(TokenAuthentication):
    keyword = "Bearer"

    def authenticate_credentials(self, key: str) -> Tuple[Any, dict]:
        try:
            token: dict = self.decode_token(key)
        except jwt.exceptions.PyJWTError as exc:
            log.info(f"Token decode error: {exc}")
            raise AuthenticationFailed("Invalid token")

        return (StubUser(), token)

    def decode_token(self, token: str) -> dict:
        jwks_client = PyJWKClient(self.get_jwks_uri())
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        return decode(
            jwt=token,
            key=signing_key.key,
            algorithms=self.get_algorithms(),
            options=self.get_options(),
            **self.get_kwargs(),
        )

    @staticmethod
    def get_jwks_uri() -> str:
        return settings.DRF_PYJWT["JWKS_URI"]

    @staticmethod
    def get_algorithms() -> Optional[list[str]]:
        return settings.DRF_PYJWT.get("ALGORITHMS")

    @staticmethod
    def get_options() -> Optional[dict]:
        return settings.DRF_PYJWT.get("OPTIONS")

    @staticmethod
    def get_kwargs() -> dict:
        return settings.DRF_PYJWT.get("KWARGS") or {}
