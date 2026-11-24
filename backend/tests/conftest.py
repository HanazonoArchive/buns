import os
import sys
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="buns-test-")
os.environ.update({
    "BUNS_DATABASE_URL": f"sqlite:///{_tmp}/buns.db",
    "BUNS_DATA_DIR": _tmp,
    "BUNS_ALLOWED_HOSTS": "localhost,127.0.0.1,juice-shop",
    "ZAP_URL": "http://127.0.0.1:9",  # nothing listens here: ZAP is skipped
    "DEEPSEEK_API_KEY": "",
    "BUNS_SEED_TARGET": "",
})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_juice_shop import FakeJuiceShop  # noqa: E402


@pytest.fixture(scope="session")
def juice():
    with FakeJuiceShop() as server:
        yield server


ADMIN_EMAIL = "sadmin@buns.com"
ADMIN_PASSWORD = "test-admin-pass-1"


def sign_in(client, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD):
    """Sign the client in as the superadmin, doing the first-run password change if needed."""
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    if r.status_code == 401 and email == ADMIN_EMAIL:
        r = client.post("/api/auth/login", json={"email": email, "password": "buns"})
        assert r.status_code == 200, r.text
        r = client.post("/api/auth/change-password", json={"current_password": "buns", "new_password": password})
    assert r.status_code == 200, r.text
    return r.json()
