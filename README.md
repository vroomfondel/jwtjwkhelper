![mypy and pytests](https://github.com/vroomfondel/jwtjwkhelper/actions/workflows/mypynpytests.yml/badge.svg)
![Cumulative Clones](https://img.shields.io/endpoint?logo=github&url=https://gist.githubusercontent.com/vroomfondel/a40d7876ff29aa14f40d7dc17796752e/raw/jwtjwkhelper_clone_count.json)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/jwtjwkhelper?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPi+Downloads)](https://pepy.tech/projects/jwtjwkhelper)

[![https://github.com/vroomfondel/jwtjwkhelper/raw/main/Gemini_Generated_Image_jwtjwkhelper_eqesiqeqesiqeqes_250x250.png](https://github.com/vroomfondel/jwtjwkhelper/raw/main/Gemini_Generated_Image_jwtjwkhelper_eqesiqeqesiqeqes_250x250.png)](https://github.com/vroomfondel/jwtjwkhelper)


# JWTJWKHelper

Lightweight helper utilities for working with JSON Web Tokens (JWT), including creating and verifying HS256 and RS256 tokens, managing RSA key pairs (PEM/JWK), and producing JWK Set structures.

- Repository: https://github.com/vroomfondel/jwtjwkhelper
- Package: `jwtjwkhelper`

## Overview

This library wraps common JWT/JWK tasks so you can:
- Generate RSA key pairs and write/read them from disk (PEM and JWK forms)
- Create HS256 or RS256 signed JWTs
- Verify JWTs (optionally with expiration verification and leeway)
- Build JWK Set (`jwks`) structures for distribution

It is intended as a small utility library you can import into your projects. There is no CLI entry point at the moment.

## Stack and Requirements

- Language: Python (>= 3.12)
- Build backend: `hatchling`
- Package manager: standard `pip`/`venv` (no lock file)
- Test framework: `pytest`
- Type checking: `mypy` (default settings; no project-specific config file committed)
- Formatting/Lint: `black` (via CI/pre-commit)

Runtime dependencies (see `pyproject.toml`):
- `loguru`
- `pyjwt`
- `jwcrypto`
- `pytz`

Development requirements are listed in `requirements-dev.txt`.

## Installation

### From source (via Makefile)

The repository includes a Makefile that sets up a local virtual environment and installs all development dependencies.

```bash
git clone https://github.com/vroomfondel/jwtjwkhelper.git
cd jwtjwkhelper

# Install dev requirements into a local .venv (created automatically)
make install

# Optional: activate the venv if you want to run Python commands manually
source .venv/bin/activate  # on Windows: .venv\Scripts\activate
```

### From PyPI

```bash
pip install jwtjwkhelper
```

## Common tasks (Makefile)

The Makefile wraps the most common developer tasks and will auto-activate the local venv for each command.

- Show help/targets
  - `make help`
- Run tests
  - `make tests`
- Format with black
  - `make lint`
- Sort imports with isort
  - `make isort`
- Static type checks with mypy
  - `make tcheck`
- Run pre-commit checks on all files
  - `make commit-checks`
- Full local validation before committing/PR
  - `make prepare`  (runs tests + commit-checks)
- Build distribution artifacts (wheel + sdist) using hatch
  - `make pypibuild`
- Publish to PyPI (requires credentials configured for hatch)
  - `make pypipush`

Note: For commands that are not Make targets (e.g., running ad-hoc Python snippets), activate the venv first: `source .venv/bin/activate`.

Notes:
- The Makefile creates a virtual environment using `python3.14`. Ensure Python 3.14 is available on your system, or create/activate a venv manually and run the commands without the Makefile.

## Quick Start

```python
from datetime import timedelta
from jwtjwkhelper.jwtjwkhelper import (
    create_jwt_hs256,
    create_jwt_rs256,
    get_verified_payload_rs256hs256,
    create_rsa_key_pairs_return_as_pem,
    get_pubkey_as_jwksetkeyentry,
)

# Create an HS256 token
payload = {"sub": "alice", "role": "admin"}
jwt_hs256 = create_jwt_hs256(payload, keyid="my-hs-key", key="super-secret", 
                             expiration_delta=timedelta(minutes=15))

# Verify HS256 or RS256 token (algorithm is auto-handled by helper)
verified_payload = get_verified_payload_rs256hs256(jwt_hs256, key="super-secret")

# Generate RSA key pairs (PEM in-memory)
key_pairs = create_rsa_key_pairs_return_as_pem(amount=1)
priv_pem = key_pairs[0].private_key
pub_pem = key_pairs[0].public_key

# Create an RS256 token (optionally include a JKU)
jwt_rs256 = create_jwt_rs256(payload, keyid="my-rsa-key", privkey_as_pem=priv_pem, 
                             jku=None, expiration_delta=timedelta(minutes=15))

# Produce a JWK Set entry for the public key
jwk_set_entry = get_pubkey_as_jwksetkeyentry(pub_pem, keyid="my-rsa-key")
```

## API Surface (selected)

Module: `jwtjwkhelper.jwtjwkhelper`

- `create_jwt_hs256(payload: dict, keyid: str, key: str, expiration_delta: timedelta = timedelta(minutes=60)))`
- `create_jwt_rs256(payload: dict, keyid: str, privkey_as_pem: str, jku: Optional[str] = None, expiration_delta: timedelta = timedelta(minutes=60))`
- `get_verified_payload_rs256hs256(jwttoken: str, key: str, leeway_in_s: int = 10, verify_exp: bool = True)`
- `get_unverified_payload(jwttoken: str)`
- `get_unverified_header(jwttoken: str)`
- `get_key_id(jwttoken: str)`
- `create_rsa_key_pairs_return_as_pem(amount: int = 3, keylength: Literal[2048, 3072, 4096] = 3072, private_key_password: Optional[bytes] = None)`
- `create_rsa_key_pairs_and_write_to_keydir(...)`
- `get_keys_in_keydir_as_jkset_dict(...)`
- `write_private_key(...)`, `write_public_key(...)`, `read_private_key(...)`, `read_public_key(...)`

For full behavior and parameters, see the function docstrings and `jwtjwkhelper/jwtjwkhelper.py`.

## Environment Variables

- None required by default.
- `TZ` (optional): timezone string used for formatting dates in this module; defaults to `Europe/Berlin`. Example: `TZ=UTC`.
- TODO: Document any additional optional env vars if/when introduced (e.g., default key directory, passwords via env, etc.).

## Scripts

- `scripts/update_badge.py`: helper used by CI to update the repository clone/download badge.

## Running Tests

```bash
pytest -q
```

`pytest.ini` is provided. A basic smoke test is included in `tests/test_base.py`.

## Development

Recommended workflow:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# formatting and type checking (if you use these locally)
python -m black .
python -m mypy .

# run tests
pytest -q
```

CI:
- GitHub Actions badges are included at the top of this README.
- TODO: Verify the workflow file names/paths in the repository (e.g., `mypynpytests.yml`, `checkblack.yml`) and update the badges if they change.

## Project Structure

```
.
├── LICENSE.md
├── LICENSEGPL.md
├── LICENSELGPL.md
├── LICENSEMIT.md
├── LICENSEPPA.txt
├── Makefile
├── README.md
├── jwtjwkhelper/
│   ├── __init__.py
│   └── jwtjwkhelper.py
├── dist/
│   ├── jwtjwkhelper-<version>.tar.gz
│   └── jwtjwkhelper-<version>-py3-none-any.whl
├── pyproject.toml
├── pytest.ini
├── requirements.txt
├── requirements-dev.txt
├── requirements-build.txt
├── scripts/
│   └── update_badge.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    └── test_base.py
```

## Building and Publishing

This project uses `hatchling` as the build backend.

Build with the standard build toolchain:

```bash
pip install build
python -m build
```

Alternatively, if you prefer `hatch`:

```bash
pip install hatch
hatch build
```

Artifacts will be written to the `dist/` directory.

Publishing:
- The Makefile provides `make pypibuild` and `make pypipush` targets (uses `hatch`).
- Authentication for `hatch publish` typically uses `HATCH_INDEX_USER` and `HATCH_INDEX_AUTH` environment variables.
- TODO: Document the exact release process (tags, changelog, versioning policy) if/when standardized.

## License

MIT License — see `LICENSE.md`.

## Links

- Homepage: https://github.com/vroomfondel/jwtjwkhelper
- Issues: use the GitHub repository issue tracker.


## ⚠️ Disclaimer

This is a development/experimental project. For production use, review security settings, customize configurations, and test thoroughly in your environment. Provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software. Use at your own risk.