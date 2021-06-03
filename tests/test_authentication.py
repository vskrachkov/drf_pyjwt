import json
from typing import ClassVar

import httpretty
from django.test import SimpleTestCase, override_settings, RequestFactory
from rest_framework.exceptions import AuthenticationFailed

from authentication import PyJWTAuthentication

_JWKS = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "0wtlJRY9-ru61LmOgieeI7_rD1oIna9QpBMAOWw8wTuoIhFQFwcIi7MFB7IEfelCPj08vkfLsuFtR8cG07EE4uvJ78bAqRjMsCvprWp4e2p7hqPnWcpRpDEyHjzirEJle1LPpjLLVaSWgkbrVaOD0lkWkP1T1TkrOset_Obh8BwtO-Ww-UfrEwxTyz1646AGkbT2nL8PX0trXrmira8GnrCkFUgTUS61GoTdb9bCJ19PLX9Gnxw7J0BtR0GubopXq8KlI0ThVql6ZtVGN2dvmrCPAVAZleM5TVB61m0VSXvGWaF6_GeOhbFoyWcyUmFvzWhBm8Q38vWgsSI7oHTkEw",
            "e": "AQAB",
            "kid": "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw",
            "x5t": "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw",
            "x5c": [
                "MIIDBzCCAe+gAwIBAgIJNtD9Ozi6j2jJMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi04N2V2eDlydS5hdXRoMC5jb20wHhcNMTkwNjIwMTU0NDU4WhcNMzMwMjI2MTU0NDU4WjAhMR8wHQYDVQQDExZkZXYtODdldng5cnUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wtlJRY9+ru61LmOgieeI7/rD1oIna9QpBMAOWw8wTuoIhFQFwcIi7MFB7IEfelCPj08vkfLsuFtR8cG07EE4uvJ78bAqRjMsCvprWp4e2p7hqPnWcpRpDEyHjzirEJle1LPpjLLVaSWgkbrVaOD0lkWkP1T1TkrOset/Obh8BwtO+Ww+UfrEwxTyz1646AGkbT2nL8PX0trXrmira8GnrCkFUgTUS61GoTdb9bCJ19PLX9Gnxw7J0BtR0GubopXq8KlI0ThVql6ZtVGN2dvmrCPAVAZleM5TVB61m0VSXvGWaF6/GeOhbFoyWcyUmFvzWhBm8Q38vWgsSI7oHTkEwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQlGXpmYaXFB7Q3eG69Uhjd4cFp/jAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAIzQOF/h4T5WWAdjhcIwdNS7hS2Deq+UxxkRv+uavj6O9mHLuRG1q5onvSFShjECXaYT6OGibn7Ufw/JSm3+86ZouMYjBEqGh4OvWRkwARy1YTWUVDGpT2HAwtIq3lfYvhe8P4VfZByp1N4lfn6X2NcJflG+Q+mfXNmRFyyft3Oq51PCZyyAkU7bTun9FmMOyBtmJvQjZ8RXgBLvu9nUcZB8yTVoeUEg4cLczQlli/OkiFXhWgrhVr8uF0/9klslMFXtm78iYSgR8/oC+k1pSNd1+ESSt7n6+JiAQ2Co+ZNKta7LTDGAjGjNDymyoCrZpeuYQwwnHYEHu/0khjAxhXo="
            ],
        },
    ]
}
_ANOTHER_JWKS = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "qMDEywqsPbiQbnSPVoKOb1HrQ_2KxI4JDe-AK-kbpb2Q3QXFl6IM3pJCvfYOm-f3DuEtBpll_Rg28WWeXl8pXAhmHk3V2Ig57f81uzGXg5xFtZDrqAG0chgwCQPD15FG00xrLDTvSDkIEPJZq-Y4IlJ3NbzQ8gn_JiappjMc8FjqQMz_4uUF-iIPU_aUgbLLtN98moKeNLAVV2lV3H5kVhNP8Fqd6piiH-mdma_KdY--GahAFC7Lt72_QtxnxowalbdkdMDim7paTeqxoZUKKHJsRVPXbiGx1zB3cfgBH7meU8ILv7JX3odu0juy0y2gagSaMkEd9-mcTLr8Bg0-5Q",
            "e": "AQAB",
            "kid": "Dt0jkFkY7KkmYdDb2BaI1",
            "x5t": "lhmczC7hbLpBZh6MBSygH1D9qeE",
            "x5c": [
                "MIIDBzCCAe+gAwIBAgIJHjJKyTNJE/wIMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi04N2V2eDlydS5hdXRoMC5jb20wHhcNMjAwMzExMjA1OTM5WhcNMzMxMTE4MjA1OTM5WjAhMR8wHQYDVQQDExZkZXYtODdldng5cnUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqMDEywqsPbiQbnSPVoKOb1HrQ/2KxI4JDe+AK+kbpb2Q3QXFl6IM3pJCvfYOm+f3DuEtBpll/Rg28WWeXl8pXAhmHk3V2Ig57f81uzGXg5xFtZDrqAG0chgwCQPD15FG00xrLDTvSDkIEPJZq+Y4IlJ3NbzQ8gn/JiappjMc8FjqQMz/4uUF+iIPU/aUgbLLtN98moKeNLAVV2lV3H5kVhNP8Fqd6piiH+mdma/KdY++GahAFC7Lt72/QtxnxowalbdkdMDim7paTeqxoZUKKHJsRVPXbiGx1zB3cfgBH7meU8ILv7JX3odu0juy0y2gagSaMkEd9+mcTLr8Bg0+5QIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQxVQqyrrAtXsBznZj2GN4nfJf+sTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAGsIl6yxIG8GOkHlfcSEa4//4WDxwfw8lg6zNPri6nhYtF1kbHTO5PqUbE+kasMnvqEV5Y0QXvyxwIjLLbbYiySK6aWp5XS2Wy5hYlMjXOimAw6mwbkNVhujRsPjTY3P+bv/9eiv2zO9yEfzfmfr6jhYcmnOdTFgAujsL4AyDpUh4/jKDtDNFl6lMdn8J7DcdRNZM/8OsAk6GgZYlzStfh4aI/uE3ekJ84XAxxdHUzwDUu5B8CetmHvfxQvV9MjmozLR8SbkTEhUv4//tr8SfGc8jS78E5w8NJN6DtYVcUNweHrAlvQXRevCmBRu3D9hKARjXfTBqilBBF9nNt93mYM="
            ],
        },
    ]
}
_JWKS_URI = "https://expenses-api.sample/jwks.json"
_ANOTHER_JWKS_URI = "https://another-api.sample/jwks.json"
_EXPIRED_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"


@override_settings(
    DRF_PYJWT={
        "JWKS_URI": _JWKS_URI,
        "ALGORITHMS": ["RS256"],
        "KWARGS": {"audience": "https://expenses-api"},
    }
)
class PyJWTAuthenticationTestCase(SimpleTestCase):
    authentication: ClassVar[PyJWTAuthentication]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        httpretty.enable(verbose=True, allow_net_connect=False)
        httpretty.register_uri(
            httpretty.GET,
            _JWKS_URI,
            body=json.dumps(_JWKS),
        )
        httpretty.register_uri(
            httpretty.GET,
            _ANOTHER_JWKS_URI,
            body=json.dumps(_ANOTHER_JWKS),
        )
        cls.authentication = PyJWTAuthentication()

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        httpretty.disable()

    def setUp(self) -> None:
        self.authentication.clear_jwks_cache()

    @override_settings(
        DRF_PYJWT={
            "JWKS_URI": _JWKS_URI,
            "ALGORITHMS": ["RS256"],
            "KWARGS": {"audience": "https://expenses-api"},
            "OPTIONS": {"verify_exp": False},
        }
    )
    def test_expired_jwt_is_validated_if_disable_exp_verification(self) -> None:
        access_token_header = f"Bearer {_EXPIRED_TOKEN}"
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=access_token_header)
        self.authentication.authenticate(request)

    def test_expired_jwt(self) -> None:
        access_token_header = f"Bearer {_EXPIRED_TOKEN}"
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

    @override_settings(
        DRF_PYJWT={
            "JWKS_URI": _ANOTHER_JWKS_URI,
            "ALGORITHMS": ["RS256"],
            "KWARGS": {"audience": "https://expenses-api"},
            "OPTIONS": {"verify_exp": False},
        }
    )
    def test_jwt_signed_by_another_key(self) -> None:
        access_token_header = f"Bearer {_EXPIRED_TOKEN}"
        request = RequestFactory().get("/", HTTP_AUTHORIZATION=access_token_header)
        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    @override_settings(
        DRF_PYJWT={
            "JWKS_URI": _JWKS_URI,
            "ALGORITHMS": ["RS256"],
            "KWARGS": {"audience": "https://expenses-api"},
            "OPTIONS": {"verify_exp": False},
            "LOOKUP_USER": "tests.test_authentication.return_anon_user",
        }
    )
    def test_lookup_user(self) -> None:
        access_token_header = f"Bearer {_EXPIRED_TOKEN}"
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
