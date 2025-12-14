import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timedelta, tzinfo
from functools import lru_cache
from pathlib import Path
from typing import Any, List, Literal, Optional, Tuple, cast
from uuid import UUID

import jwcrypto.jwk as jwk
import jwt
import pytz as pytz

from loguru import logger

_tz: tzinfo = pytz.timezone(
    os.getenv("TZ", "Europe/Berlin")
)  # explicitely setting TZ for this module to Europe/Berlin if not set


class ComplexEncoder(json.JSONEncoder):
    """JSON encoder that knows how to serialize common complex types.

    Supports instances exposing a ``reprJSON`` method as well as standard
    Python types that are not natively JSON serializable such as
    ``uuid.UUID``, ``datetime``, ``date`` and ``timedelta``.
    """

    def default(self, obj: Any) -> Any:
        """Return a serializable representation for ``obj``.

        Args:
            obj: Any object that should be serialized to JSON.

        Returns:
            A JSON-serializable representation of ``obj`` (typically a str),
            or delegates to the base implementation if unsupported.
        """
        if hasattr(obj, "reprJSON"):
            return obj.reprJSON()
        elif type(obj) == UUID:
            obj = cast(UUID, obj)
            return str(obj)
        elif type(obj) == datetime:
            obj = cast(datetime, obj)
            return obj.strftime("%Y-%m-%d %H:%M:%S %Z")
        elif type(obj) == date:
            obj = cast(date, obj)
            return obj.strftime("%Y-%m-%d")
        elif type(obj) == timedelta:
            obj = cast(timedelta, obj)
            return str(obj)
        else:
            return json.JSONEncoder.default(self, obj)


def write_private_key(key: jwk.JWK, filepath: Path, private_key_password: Optional[str] = None) -> None:
    """Write a private JWK as PEM to disk.

    Args:
        key: The JWK instance containing a private key part.
        filepath: Destination path for the PEM file.
        private_key_password: Optional password to encrypt the private key.

    Raises:
        Exception: If ``key`` does not contain a private part.
    """
    if not key.has_private:
        raise Exception("Key has not private Key Part")

    with open(filepath, "wb") as f:
        f.write(key.export_to_pem(private_key=True, password=private_key_password))  # type: ignore
    logger.info(f"Written to: {filepath}")


def write_public_key(key: jwk.JWK, filepath: Path) -> None:
    """Write a public JWK as PEM to disk.

    Args:
        key: The JWK instance (public part will be exported).
        filepath: Destination path for the PEM file.
    """
    with open(filepath, "wb") as f:
        f.write(key.export_to_pem(private_key=False))
    logger.info(f"Written to: {filepath}")


def read_private_key(filepath: Path, private_key_password: Optional[bytes] = None) -> jwk.JWK:
    """Read a private key PEM from disk and return it as ``jwk.JWK``.

    Args:
        filepath: Path to the private key PEM file.
        private_key_password: Optional password used to decrypt the key.

    Returns:
        The loaded private key as a ``jwk.JWK`` instance.
    """
    with open(filepath, "rb") as f:
        keyd = f.read()
        key = jwk.JWK.from_pem(keyd, private_key_password)
        logger.info(f"Read from {filepath} hasPrivateKey: {key.has_private}")
        return key


def read_public_key(filepath: Path) -> jwk.JWK:
    """Read a public key PEM from disk and return it as ``jwk.JWK``.

    Args:
        filepath: Path to the public key PEM file.

    Returns:
        The loaded public key as a ``jwk.JWK`` instance.
    """
    with open(filepath, "rb") as f:
        keyd = f.read()
        key = jwk.JWK.from_pem(keyd)
        logger.info(f"Read from {filepath} hasPrivateKey: {key.has_private}")
        return key


def get_key_id(jwttoken: str) -> Optional[str]:
    """Extract the ``kid`` (Key ID) from a JWT.

    Tries the unverified header first and falls back to the unverified
    payload. Any errors are logged and ``None`` is returned.

    Args:
        jwttoken: The encoded JWT string.

    Returns:
        The Key ID as string if present, else ``None``.
    """
    try:
        headers: dict = jwt.get_unverified_header(jwttoken)
        if "kid" in headers:
            return headers.get("kid")

        decoded_unverified: dict = get_unverified_payload(jwttoken)

        key_id: str = cast(str, decoded_unverified.get("kid"))

        return key_id
    except Exception as ex:
        logger.exception(jwttoken, exception=ex)
    return None


def get_unverified_payload(jwttoken: str) -> dict[str, Any]:
    """Decode a JWT without verifying the signature and return its payload.

    Requires the presence of ``kid`` and ``exp`` claims.

    Args:
        jwttoken: The encoded JWT string.

    Returns:
        The decoded payload as a dictionary.
    """
    decoded_unverified: dict[str, Any] = jwt.decode(jwttoken, verify=False, options={"require": ["kid", "exp"]})
    return decoded_unverified


def get_unverified_header(jwttoken: str) -> dict[str, Any]:
    """Return the unverified header of a JWT.

    Args:
        jwttoken: The encoded JWT string.

    Returns:
        The decoded header as a dictionary.
    """
    decoded_unverified: dict = jwt.get_unverified_header(jwttoken)
    return decoded_unverified


def get_verified_payload_rs256hs256(
    jwttoken: str,
    key: str,  # either key in PEM format for RS256 OR secret-key-str for HS256
    leeway_in_s: int = 10,
    verify_exp: bool = True,
) -> Optional[dict]:
    """Verify and decode a JWT signed with RS256 or HS256.

    Args:
        jwttoken: The encoded JWT string.
        key: Verification key. For RS256 provide the public key PEM; for
            HS256 provide the shared secret string.
        leeway_in_s: Allowed clock skew in seconds for ``exp`` verification.
        verify_exp: Whether to enforce expiration verification.

    Returns:
        The decoded payload as a dictionary if verification succeeds,
        otherwise ``None`` (errors are logged).
    """
    try:
        decoded: dict = jwt.decode(
            jwttoken,
            key,
            leeway=timedelta(seconds=leeway_in_s),
            algorithms=["RS256", "HS256"],
            verify=True,
            options={
                # "verify_aud": False,
                "verify_exp": verify_exp,
                "require": ["exp", "kid"],
                # options={"verify_signature": False})
            },
        )

        return decoded
    except jwt.exceptions.ExpiredSignatureError as e1:
        logger.exception(jwttoken, exception=e1)

    return None


def create_jwt_hs256(payload: dict, keyid: str, key: str, expiration_delta: timedelta = timedelta(minutes=60)) -> str:
    """Create a HS256-signed JWT.

    Adds ``exp`` and ``kid`` claims to the payload and signs with the
    provided secret.

    Args:
        payload: The payload (will be mutated by adding ``exp`` and ``kid``).
        keyid: The Key ID to set in payload and header.
        key: The HS256 shared secret.
        expiration_delta: Time delta from now used to compute ``exp``.

    Returns:
        The encoded JWT string.
    """
    payload["exp"] = datetime.utcnow() + expiration_delta
    payload["kid"] = keyid
    token = jwt.encode(payload, key, algorithm="HS256", headers={"kid": keyid}, json_encoder=ComplexEncoder)
    return token


def create_jwt_rs256(
    payload: dict,
    keyid: str,
    privkey_as_pem: str,
    jku: Optional[str] = None,
    expiration_delta: timedelta = timedelta(minutes=60),
) -> str:
    """Create a RS256-signed JWT.

    Adds ``exp`` and ``kid`` claims to the payload and optionally a ``jku``
    header. Signs with the provided private key in PEM format.

    Args:
        payload: The payload (will be mutated by adding ``exp`` and ``kid``).
        keyid: The Key ID to set in payload and header.
        privkey_as_pem: The private key in PEM format used to sign.
        jku: Optional JWK set URL to include in header.
        expiration_delta: Time delta from now used to compute ``exp``.

    Returns:
        The encoded JWT string.
    """
    payload["exp"] = datetime.utcnow() + expiration_delta
    payload["kid"] = keyid

    headers: dict = {"kid": keyid}
    if jku:
        headers["jku"] = jku

    token = jwt.encode(payload, privkey_as_pem, algorithm="RS256", headers=headers, json_encoder=ComplexEncoder)
    return token


@lru_cache
def get_key_pair_pem_from_key_id_in_keydir(
    keyid: str, modname: str = "JWTJWKHelper", keydir: Path = Path.home(), private_key_password: Optional[bytes] = None
) -> Tuple[str, str]:
    """Load key pair PEM strings for a given key id from a key directory.

    Args:
        keyid: The identifier suffix used in the filename pattern.
        modname: Module/application name prefix for the key files.
        keydir: The directory where key files are stored.
        private_key_password: Optional password to decrypt the private key.

    Returns:
        A tuple ``(private_key_pem, public_key_pem)`` of strings.
    """

    pubkey_jwk: jwk.JWK
    privkey_jwk: jwk.JWK

    pubkey_jwk, privkey_jwk = get_key_pair_jwk_from_key_id_in_keydir(keyid, modname, keydir, private_key_password)

    pubkey_pem: str = pubkey_jwk.export_to_pem(private_key=False, password=None).decode()
    privkey_pem: str = privkey_jwk.export_to_pem(private_key=True, password=None).decode()  # decode plain in ram

    return (privkey_pem, pubkey_pem)


def get_key_pair_jwk_from_key_id_in_keydir(
    keyid: str, modname: str = "JWTJWKHelper", keydir: Path = Path.home(), private_key_password: Optional[bytes] = None
) -> Tuple[jwk.JWK, jwk.JWK]:
    """Load key pair as ``jwk.JWK`` for a given key id from a key directory.

    Args:
        keyid: The identifier suffix used in the filename pattern.
        modname: Module/application name prefix for the key files.
        keydir: The directory where key files are stored.
        private_key_password: Optional password to decrypt the private key.

    Returns:
        A tuple ``(private_key_jwk, public_key_jwk)``.
    """

    privkeypath: Path = Path(keydir, f"{modname}_priv_{keyid}.pem")
    pubkeypath: Path = Path(keydir, f"{modname}_pub_{keyid}.pem")

    pubkey_jwk: jwk.JWK = read_public_key(pubkeypath)
    privkey_jwk: jwk.JWK = read_private_key(privkeypath, private_key_password=private_key_password)

    return (privkey_jwk, pubkey_jwk)


@dataclass
class RSAKeyPairPEM:
    """Dataclass container for an RSA key pair in PEM format."""

    privatekey_pem: str
    publickey_pem: str


def create_rsa_key_pairs_return_as_pem(
    amount: int = 3, keylength: Literal[2048, 3072, 4096] = 3072, private_key_password: Optional[bytes] = None
) -> List[RSAKeyPairPEM]:
    """Generate RSA key pairs and return them as PEM strings.

    Args:
        amount: Number of key pairs to generate.
        keylength: RSA key size in bits.
        private_key_password: Optional password to encrypt private keys.

    Returns:
        A list of ``RSAKeyPairPEM`` instances.
    """

    ret = []
    for i in range(0, amount):
        key: jwk.JWK = jwk.JWK.generate(kty="RSA", size=keylength)

        t: RSAKeyPairPEM = RSAKeyPairPEM(
            privatekey_pem=key.export_to_pem(private_key=True, password=private_key_password).decode(
                "utf-8"
            ),  # ascii would have been the same -> its PEM!
            publickey_pem=key.export_to_pem(private_key=False).decode(
                "utf-8"
            ),  # ascii would have been the same -> its PEM!
        )

        ret.append(t)
    return ret


def get_pubkey_as_jwksetkeyentry(pubkey_as_pem: str, keyid: str) -> dict:
    """Convert a public key PEM to a JWK Set key entry dict.

    Adds standard JWK fields and sets ``alg``, ``use`` and ``kid``.

    Args:
        pubkey_as_pem: Public key in PEM format.
        keyid: Key ID to include in the JWK entry.

    Returns:
        A dictionary suitable for inclusion in a JWK Set under ``keys``.
    """
    pubkey_jwk: jwk.JWK = jwk.JWK.from_pem(pubkey_as_pem.encode("utf-8"))

    dp: dict[str, Any] = pubkey_jwk.export_public(True)
    dp["alg"] = "RS256"
    dp["use"] = "sig"
    dp["kid"] = keyid

    return dp


def create_rsa_key_pairs_and_write_to_keydir(
    amount: int = 10,
    modname: str = "JWTJWKHelper",
    keydir: Path = Path.home(),
    keylength: Literal[2048, 3072, 4096] = 3072,
    private_key_password: Optional[str] = None,
) -> List[Tuple[Path, Path, str]]:
    """Generate RSA key pairs and store them as PEM files in ``keydir``.

    Files are written using the pattern ``{modname}_priv_{keyid}.pem`` and
    ``{modname}_pub_{keyid}.pem``. The function returns the paths and keyids.

    Args:
        amount: Number of key pairs to generate.
        modname: Module/application name prefix used in filenames.
        keydir: Destination directory for key files.
        keylength: RSA key size in bits.
        private_key_password: Optional password to encrypt private keys.

    Returns:
        A list of tuples ``(private_key_path, public_key_path, keyid)``.
    """
    now: datetime = datetime.now()
    nowstr: str = now.strftime("%Y%m%d%H%M")

    ret = []
    for i in range(0, amount):
        key: jwk.JWK = jwk.JWK.generate(kty="RSA", size=keylength)
        keyid: str = f"{nowstr}-{i}"

        logger.debug(f"JWK_KEY[{i}],{keyid=}: ", json.dumps(key.export_public(as_dict=True), indent=4, sort_keys=True))

        privkeypath: Path = Path(keydir, f"{modname}_priv_{keyid}.pem")
        pubkeypath: Path = Path(keydir, f"{modname}_pub_{keyid}.pem")

        write_private_key(key, privkeypath, private_key_password=private_key_password)
        write_public_key(key, pubkeypath)

        ret.append((privkeypath, pubkeypath, keyid))

    return ret


@lru_cache
def get_keys_in_keydir_as_jkset_dict(
    modname: str = "JWTJWKHelper", keydir: Path = Path.home(), private_key_password: Optional[bytes] = None
) -> dict:
    """Load all keys in ``keydir`` and return them as a JWK Set dict.

    Scans for files matching the private key pattern and builds the
    corresponding public JWK entries.

    Args:
        modname: Module/application name prefix used in filenames.
        keydir: Directory to scan for key files.
        private_key_password: Optional password to decrypt private keys.

    Returns:
        A dictionary in JWK Set format: ``{"keys": [ ... ]}``.
    """
    # jws: jwk.JWKSet = jwk.JWKSet()

    ret: dict[str, List[dict[str, Any]]] = {"keys": []}

    for f in keydir.glob(f"{modname}_priv_????????????-?.pem"):
        keyid = f.name.split("_")[2].split(".")[0]
        privkeyJWK, pubkeyJWK = get_key_pair_jwk_from_key_id_in_keydir(
            keyid, modname, keydir, private_key_password=private_key_password
        )

        dp: dict[str, Any] = pubkeyJWK.export_public(True)
        dp["alg"] = "RS256"
        dp["use"] = "sig"
        dp["kid"] = keyid

        ret["keys"].append(dp)

    return ret
