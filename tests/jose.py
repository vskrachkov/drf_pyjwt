import jwcrypto.jwk
import jwcrypto.jwt


def create_key(kid: str) -> jwcrypto.jwk.JWK:
    return jwcrypto.jwk.JWK.generate(kty="RSA", kid=kid, use="sig")


def create_jwks_response_body(key: jwcrypto.jwk.JWK) -> str:
    return jwcrypto.jwk.JWKSet(keys=key).export(private_keys=False)


def create_token(key: jwcrypto.jwk.JWK, aud: str, iss: str, exp: int, iat: int) -> str:
    jwt = jwcrypto.jwt.JWT(
        header={"type": "JWT", "alg": "RS256", "kid": key.key_id},
        claims={"aud": aud, "iss": iss, "exp": exp, "iat": iat},
    )
    jwt.make_signed_token(key)
    return jwt.serialize()
