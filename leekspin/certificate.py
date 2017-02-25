# -*- coding: utf-8 -*-
"""Main leekspin module for generating mocked Ed25519 certificates for use in descriptors
"""

import base64
import hashlib
import time
import warnings

warnings.simplefilter('ignore', UserWarning, append=True)

try:
    import nacl
    import nacl.signing
    import nacl.encoding
except (ImportError, NameError, IOError) as error:
    print("This script requires pyNaCl>=0.2.3")
    raise SystemExit(error.message)

from leekspin import const
from leekspin import crypto
from leekspin import util
from leekspin.crypto import longToBytes

def signDescriptor(sksigning, descriptor):
    """Signs the descriptor with the provided Ed25519 Signing Key

    Prepends the required 'Tor router descriptor signature v1' suffix to the
    descriptor text before signing it as specified by prop #220

    :param nacl.signing.SigningKey sksigning: the key with which to generate the signature
    :param str descriptor: the descriptor content to be signed.

    :returns: the descriptor with the appropriate router-sig-ed25519 line suffixed"""
    descriptor += const.TOKEN_ED25519_ROUTER_SIGNATURE
    sha256digest = hashlib.sha256(const.TOKEN_ED25519_DESCRIPTOR_SIGNATURE_PREFIX + descriptor).digest()
    descriptor += b"%s\n" % util.stripBase64Padding(base64.b64encode(sksigning.sign(sha256digest).signature))
    return descriptor

def generateIdentitySigningKeys():
    """Generate new Identity and Signing Ed25519 keys

    :returns: a tuple of 2 nacl.signing.SigningKey objects and the appropriate
    ``master-key-ed25519`` descriptor line
    """
    (skidentity, sksigning) = (nacl.signing.SigningKey.generate(), nacl.signing.SigningKey.generate())

    return (
        skidentity,
        sksigning,
        const.TOKEN_ED25519_MASTER_KEY + util.stripBase64Padding(skidentity.verify_key.encode(nacl.encoding.Base64Encoder))
    )

def generateCertificateLine(skidentity, sksigning):
    """Generate a ``identity-ed25519`` line given the identity and signing keys

    :param nacl.signing.SigningKey skidentity: The Ed25519 secret identity / master key.
    :param nacl.signing.SigningKey sksigning: The Ed25519 signing key to be certified.
    :returns: The appropriate ``identity-ed25519`` line"""

    cert_data = _generateCertificate(skidentity, sksigning)
    cert_encoded = base64.b64encode(cert_data)
    cert_encoded_chunked = crypto.chunkInto64CharsPerLine(cert_encoded)
    return const.TOKEN_ED25519_IDENTITY + _addCertificateHeaderAndFooter(cert_encoded_chunked)

def _addCertificateHeaderAndFooter(certificate):
    """Add the ``-----BEGIN ED25519 CERT-----`` and ``-----END ED25519 CERT-----`` headers to a **certificate**.

    :param bytes certificate: A headerless, chunked, base64-encoded Ed25519 certificate.
    :rtype: bytes
    :returns: The same certificate, with the headers Tor uses around it.
    """
    return b'\n'.join([const.ED25519_BEGIN_CERT, certificate, const.ED25519_END_CERT])

def _generateCertificate(skidentity, sksigning):
    """Generate a Ed25519 Signing Key Certificate

    :param nacl.signing.SigningKey skidentity: The Ed25519 secret identity / master key
    :param nacl.signing.SigningKey sksigning: The Ed25519 secret signing key
    """

    cert_data = ''
    cert_data += '\x01' # CertVersion
    cert_data += '\x04' # CertType
    cert_data += longToBytes(((time.time() / 3600) + (24 * 30)) , blocksize=4) # ExpirationDate (30 days in future)
    cert_data += '\x01' # CertKeyType
    cert_data += sksigning.verify_key.__bytes__() # CertifiedKey
    cert_data += '\x01' # NExtensions
    extensions = _generateSignedWithEd25519KeyExtension(skidentity.verify_key)
    cert_data += extensions # SignedWithEd25519KeyCertificateExtension

    cert_data += skidentity.sign(cert_data).signature # Signature

    return cert_data

def _generateSignedWithEd25519KeyExtension(pkidentity):
    """Generate a SignedWithEd25519KeyCertificateExtension with the corresponding ed25519 public key

    :param nacl.signing.VerifyKey pkidentity: the Ed25519 public identity / master key
    :rtype: bytes
    :returns: The generated extension bytestring
    """
    ext_data = ''
    ext_data += '\00 ' # ExtLength
    ext_data += '\x04' # ExtType
    ext_data += '\x01' # ExtFlags
    ext_data += pkidentity.__bytes__() # ExtData

    return ext_data

