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
