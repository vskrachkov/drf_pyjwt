import time
from typing import ClassVar

import httpretty
from django.test import SimpleTestCase, override_settings, RequestFactory
from rest_framework.exceptions import AuthenticationFailed

from authentication import PyJWTAuthentication
from . import jose

_JWKS_URI = "https://app.domain.sample/jwks.json"
_ANOTHER_JWKS_URI = "https://another-api.sample/jwks.json"


@override_settings(
    DRF_PYJWT_JWKS_URI=_JWKS_URI,
    DRF_PYJWT_ALGORITHMS=["RS256"],
    DRF_PYJWT_KWARGS={"audience": "https://app.domain"},
)
class PyJWTAuthenticationTestCase(SimpleTestCase):
    authentication: ClassVar[PyJWTAuthentication]
    expired_token: ClassVar[str]
    valid_token: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.authentication = PyJWTAuthentication()

        key = jose.create_key("1111")
        httpretty.register_uri(
            httpretty.GET,
            _JWKS_URI,
            body=jose.create_jwks_response_body(key),
        )
        cls.expired_token = jose.create_token(
            key, aud="https://app.domain", iss="", exp=0, iat=0
        )
        cls.valid_token = jose.create_token(
            key, aud="https://app.domain", iss="", exp=int(time.time() + 300), iat=0
        )

        key = jose.create_key("1111")
        httpretty.register_uri(
            httpretty.GET,
            _ANOTHER_JWKS_URI,
            body=jose.create_jwks_response_body(key),
        )

        httpretty.enable(verbose=True, allow_net_connect=False)

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        httpretty.disable()

    def setUp(self) -> None:
        self.authentication.clear_jwks_cache()

    def test_expired_jwt_is_validated_if_disable_exp_verification(self) -> None:
        access_token_header = f"Bearer {self.valid_token}"
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=access_token_header)
        self.authentication.authenticate(request)

    def test_expired_jwt(self) -> None:
        access_token_header = f"Bearer {self.expired_token}"
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=access_token_header)
        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_empty_authorization_header(self) -> None:
        request = RequestFactory().get("/", HTTP_AUTHORIZATION="")
        result = self.authentication.authenticate(request)
        self.assertIsNone(result)

    def test_malformed_jwt_in_authorization_header(self) -> None:
        request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer malformed-token")
        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    @override_settings(DRF_PYJWT_JWKS_URI=_ANOTHER_JWKS_URI)
    def test_jwt_signed_by_another_key(self) -> None:
        access_token_header = f"Bearer {self.valid_token}"
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=access_token_header)
        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    @override_settings(
        DRF_PYJWT_LOOKUP_USER="tests.test_authentication.return_anon_user"
    )
    def test_lookup_user(self) -> None:
        access_token_header = f"Bearer {self.valid_token}"
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=access_token_header)
        result = self.authentication.authenticate(request)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        user, token = result
        self.assertIsInstance(user, FakeUser)


class FakeUser:
    pass


def return_anon_user(token: dict) -> FakeUser:
    return FakeUser()
