import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.crypto_provider import CryptoProvider


@pytest.fixture
def crypto_provider():
    return CryptoProvider()


@pytest.fixture
def keys(crypto_provider):
    return crypto_provider.generate_keys()


def test_generate_keys(crypto_provider):
    private_key, public_key = crypto_provider.generate_keys()
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_sign_and_verify_success(crypto_provider, keys):
    private_key, public_key = keys
    data = "Test data for signing"

    signature = crypto_provider.sign(data, private_key)

    is_valid = crypto_provider.verify(data, signature, public_key)
    assert is_valid is True


def test_verify_invalid_signature(crypto_provider, keys):
    _, public_key = keys
    data = "Test data for signing"
    invalid_signature = b'invalidsignature'

    is_valid = crypto_provider.verify(data, invalid_signature, public_key)
    assert is_valid is False


def test_sign_with_different_data(crypto_provider, keys):
    private_key, public_key = keys
    data = "Original data"
    different_data = "Modified data"

    signature = crypto_provider.sign(data, private_key)

    is_valid = crypto_provider.verify(different_data, signature, public_key)
    assert is_valid is False
