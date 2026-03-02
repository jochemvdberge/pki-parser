from __future__ import annotations
import datetime
from typing import Dict, Any, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    # raise a clearer message for missing dependency
    raise RuntimeError(
        "cryptography dependency is required; install with `pip install cryptography`"
    ) from e


class X509Parser:
    """Simple parser for X.509 certificates.

    The class loads a certificate from PEM or DER bytes and provides
    a JSON-serializable dictionary of selected fields.
    """

    def __init__(self, data: bytes) -> None:
        self._cert = self._load_certificate(data)

    def _load_certificate(self, data: bytes) -> x509.Certificate:
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except ValueError:
            return x509.load_der_x509_certificate(data, default_backend())

    def get_info(self) -> Dict[str, Any]:
        cert = self._cert
        info: Dict[str, Any] = {}
        info["subject"] = self._name_to_dict(cert.subject)
        info["issuer"] = self._name_to_dict(cert.issuer)
        info["serial_number"] = hex(cert.serial_number)
        info["not_before"] = cert.not_valid_before.isoformat()
        info["not_after"] = cert.not_valid_after.isoformat()

        # public key details
        pub = cert.public_key()
        if hasattr(pub, "key_size"):
            info["key_size"] = pub.key_size
        # algorithm name based on type
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

        if isinstance(pub, rsa.RSAPublicKey):
            info["key_algorithm"] = "RSA"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info["key_algorithm"] = "ECDSA"
        elif isinstance(pub, dsa.DSAPublicKey):
            info["key_algorithm"] = "DSA"
        else:
            info["key_algorithm"] = pub.__class__.__name__

        # digest algorithm used in signature
        try:
            info["digest_algorithm"] = cert.signature_hash_algorithm.name
        except Exception:
            info["digest_algorithm"] = None

        # subject key identifier extension, if present
        try:
            ski = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ).value
            info["subject_key_identifier"] = ski.digest.hex()
        except x509.ExtensionNotFound:
            info["subject_key_identifier"] = None

        # fingerprint
        from cryptography.hazmat.primitives import hashes

        info["sha256_fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()

        return info

    def _name_to_dict(self, name: x509.Name) -> Dict[str, str]:
        return {attr.oid._name: attr.value for attr in name}

    def _extensions_to_dict(self, cert: x509.Certificate) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for ext in cert.extensions:
            result[ext.oid._name] = self._extension_value(ext)
        return result

    def _extension_value(self, ext: x509.Extension) -> Any:
        # Handle some common extensions, fall back to repr
        value = ext.value
        if isinstance(value, x509.BasicConstraints):
            return {"ca": value.ca, "path_length": value.path_length}
        if isinstance(value, x509.SubjectAlternativeName):
            return [str(name) for name in value]
        return repr(value)
