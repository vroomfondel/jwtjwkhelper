__version__ = "0.0.10"

import os
import sys
from typing import Callable, Dict, Any

from loguru import logger as glogger

glogger.disable(__name__)


def _loguru_skiplog_filter(record: dict) -> bool:
    """Filter function to hide records with ``extra['skiplog']`` set.

    Intended for use with ``loguru``'s ``filter=`` parameter so that callers can
    temporarily suppress verbose logs for specific operations by binding
    ``skiplog=True`` on the logger.

    Args:
        record (dict): Loguru record dictionary.

    Returns:
        bool: ``True`` to keep the record, ``False`` to skip it.
    """
    # {
    #     "elapsed": timedelta,      # Zeit seit Programmstart
    #     "exception": tuple,         # Exception-Info (type, value, traceback) oder None
    #     "extra": dict,             # Benutzerdefinierte Extra-Felder
    #     "file": RecordFile,        # Datei-Info (name, path)
    #     "function": str,           # Name der Funktion
    #     "level": RecordLevel,      # Level-Info (name, no, icon)
    #     "line": int,               # Zeilennummer
    #     "message": str,            # Formatierte Nachricht
    #     "module": str,             # Modulname
    #     "name": str,               # Logger-Name
    #     "process": RecordProcess,  # Process-Info (id, name)
    #     "thread": RecordThread,    # Thread-Info (id, name)
    #     "time": datetime           # Zeitstempel des Log-Eintrags
    # }
    return not record.get("extra", {}).get("skiplog", False)


def configure_loguru_default_with_skiplog_filter(
    loguru_filter: Callable[[Dict[str, Any]], bool] = _loguru_skiplog_filter,
) -> None:
    """Configure a default ``loguru`` sink with a convenient format and filter.

    This sets a colored formatter, applies the given filter (by default
    :func:`_loguru_skiplog_filter`), and ensures a reasonable default log level
    via the ``LOGURU_LEVEL`` environment variable.

    Args:
        loguru_filter: A callable taking a record dict and returning ``True``
            if the record should be emitted. Defaults to
            :func:`_loguru_skiplog_filter`.
    """
    glogger.info("configure_loguru_default_with_skiplog_filter")

    os.environ["LOGURU_LEVEL"] = os.getenv("LOGURU_LEVEL", "DEBUG")  # standard is DEBUG
    glogger.remove()  # remove default-handler
    logger_fmt: str = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{module}</cyan>::<cyan>{extra[classname]}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    # logger_fmt: str = "<g>{time:HH:mm:ssZZ}</> | <lvl>{level}</> | <c>{module}::{extra[classname]}:{function}:{line}</> - {message}"

    glogger.add(sys.stderr, level=os.getenv("LOGURU_LEVEL"), format=logger_fmt, filter=loguru_filter)  # type: ignore # TRACE | DEBUG | INFO | WARN | ERROR |  FATAL
    glogger.configure(extra={"classname": "None", "skiplog": False})


from .jwtjwkhelper import (
    get_key_pair_pem_from_key_id_in_keydir,
    get_key_pair_jwk_from_key_id_in_keydir,
    get_key_id,
    get_keys_in_keydir_as_jkset_dict,
    create_rsa_key_pairs_return_as_pem,
    create_rsa_key_pairs_and_write_to_keydir,
    write_public_key,
    write_private_key,
    read_private_key,
    read_public_key,
    create_jwt_hs256,
    create_jwt_rs256,
    get_unverified_payload,
    get_unverified_header,
    get_verified_payload_rs256hs256,
    get_pubkey_as_jwksetkeyentry,
    jwk,
)
