import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mongomock
import mongomock.collection
import pytest

from database.mongodb import MongoStore

# Patch mongomock BulkOperationBuilder.add_update to ignore 'sort' added in newer pymongo
_orig_add_update = mongomock.collection.BulkOperationBuilder.add_update


def _compat_add_update(self, *args, **kwargs):
    kwargs.pop("sort", None)
    return _orig_add_update(self, *args, **kwargs)


mongomock.collection.BulkOperationBuilder.add_update = _compat_add_update


@pytest.fixture
def store():
    return MongoStore(client=mongomock.MongoClient(), db_name="test_soc").init()
