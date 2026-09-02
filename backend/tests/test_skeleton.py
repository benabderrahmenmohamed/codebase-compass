"""Tests of the skeleton layer.

No network, no server, no subprocess: parsing only.
"""

from analysis import skeleton

PYTHON_FILE = '''"""Order handling."""

import os
from datetime import datetime

from app.models import Order

MAX_ITEMS = 50


def create_order(customer_id: int, items: list) -> Order:
    """Create an order for a customer."""
    return Order(customer_id, items)


class OrderService:
    """Business rules around orders."""

    def cancel(self, order_id: int) -> bool:
        """Cancel an order if it has not shipped."""
        return True
'''


# ---------------------------------------------------------------- python


def test_python_symbols_are_extracted():
    file = skeleton.parse_python("app/orders.py", PYTHON_FILE)

    kinds = {(symbol.kind, symbol.name) for symbol in file.symbols}
    assert ("function", "create_order") in kinds
    assert ("class", "OrderService") in kinds
    assert ("method", "OrderService.cancel") in kinds
    assert ("constant", "MAX_ITEMS") in kinds


def test_signatures_and_docstrings_are_captured():
    file = skeleton.parse_python("app/orders.py", PYTHON_FILE)
    by_name = {symbol.name: symbol for symbol in file.symbols}

    assert "customer_id" in by_name["create_order"].signature
    assert by_name["create_order"].doc == "Create an order for a customer."
    assert by_name["OrderService"].doc == "Business rules around orders."


def test_function_bodies_are_not_included():
    """The skeleton is a map, not the territory: bodies stay out."""
    file = skeleton.parse_python("app/orders.py", PYTHON_FILE)

    everything = " ".join(
        f"{s.kind}{s.name}{s.signature}{s.doc or ''}" for s in file.symbols
    )
    assert "return Order(customer_id, items)" not in everything


def test_imports_are_collected():
    file = skeleton.parse_python("app/orders.py", PYTHON_FILE)

    # `import os` is recorded as written.
    assert "os" in file.imports
    # `from X import Y` records the most specific form X.Y, so that
    # `from analysis import ingestion` can resolve to the submodule rather
    # than to the package's __init__.py. The resolver walks back up when the
    # specific form does not exist.
    assert "datetime.datetime" in file.imports
    assert "app.models.Order" in file.imports


def test_a_file_that_does_not_parse_is_recorded_not_fatal():
    file = skeleton.parse_python("app/broken.py", "def f(:\n  ???\n")

    assert file.parse_error is not None
    assert file.symbols == []
    assert file.lines == 2


def test_line_numbers_are_real():
    file = skeleton.parse_python("app/orders.py", PYTHON_FILE)
    total = len(PYTHON_FILE.splitlines())

    for symbol in file.symbols:
        assert 1 <= symbol.line <= total


# ------------------------------------------------------------ entry points


def test_a_main_guard_marks_an_entry_point():
    file = skeleton.parse_python(
        "app/tool.py", 'if __name__ == "__main__":\n    print(1)\n'
    )

    assert file.is_entry_point


def test_a_framework_call_marks_an_entry_point():
    file = skeleton.parse_python("app/api.py", "app = FastAPI()\n")

    assert file.is_entry_point


def test_a_conventional_filename_marks_an_entry_point():
    file = skeleton.parse_python("main.py", "x = 1\n")

    assert file.is_entry_point


def test_an_ordinary_module_is_not_an_entry_point():
    file = skeleton.parse_python("app/models.py", "class Order:\n    pass\n")

    assert not file.is_entry_point


def test_merely_mentioning_a_framework_is_not_an_entry_point():
    """Found by running the analyser on this project's own source.

    A text search for "FastAPI(" flagged schemas.py (which shows
    `app = FastAPI()` inside a documentation example) and skeleton.py itself
    (which lists the framework names it looks for). Detection must read the
    syntax tree, not the raw text — the exact mistake this tool exists to
    catch.
    """
    documented = skeleton.parse_python(
        "app/schemas.py",
        'EXAMPLE = "from fastapi import FastAPI\\napp = FastAPI()"\n',
    )
    commented = skeleton.parse_python("app/notes.py", "# app = FastAPI()\nx = 1\n")

    assert not documented.is_entry_point
    assert not commented.is_entry_point


def test_a_framework_mentioned_in_a_javascript_string_is_not_an_entry_point():
    file = skeleton.parse_javascript(
        "front/docs.js", "const sample = 'const app = express()'\n"
    )

    assert not file.is_entry_point


def test_a_submodule_import_does_not_credit_the_package():
    """`from analysis import ingestion` points at the submodule.

    Before the fix it resolved to analysis/__init__.py, which made an empty
    package file look like the most important file in the project.
    """
    result = skeleton.build(
        {
            "pkg/__init__.py": "",
            "pkg/tools.py": "def helper():\n    pass\n",
            "app.py": "from pkg import tools\n",
        }
    )

    assert result.imports_graph["app.py"] == ["pkg/tools.py"]
    assert result.imported_by["pkg/__init__.py"] == []


def test_a_file_declaring_nothing_does_not_lead_the_reading_order():
    result = skeleton.build(
        {
            "pkg/__init__.py": "",
            "pkg/core.py": "class Engine:\n    pass\n",
            "a.py": "from pkg.core import Engine\n",
            "b.py": "from pkg.core import Engine\n",
        }
    )

    assert skeleton.reading_order(result)[0] == "pkg/core.py"


# ------------------------------------------------------------- javascript


def test_javascript_imports_and_symbols():
    file = skeleton.parse_javascript(
        "front/app.js",
        "import React from 'react'\n"
        "import { load } from './api'\n"
        "const API_URL = 'x'\n"
        "export function render() {}\n"
        "class Widget {}\n",
    )

    assert "react" in file.imports
    assert "./api" in file.imports
    names = {symbol.name for symbol in file.symbols}
    assert {"render", "Widget", "API_URL"} <= names


def test_require_is_also_an_import():
    file = skeleton.parse_javascript("front/old.js", "const fs = require('./helpers')\n")

    assert "./helpers" in file.imports


# ------------------------------------------------------------- import graph


PROJECT = {
    "app/__init__.py": "",
    "app/main.py": "from app.models import Order\nfrom .services import run\napp = FastAPI()\n",
    "app/models.py": "import os\nclass Order:\n    pass\n",
    "app/services.py": "from app.models import Order\nimport requests\n",
    "front/index.js": "import { helper } from './utils'\nimport axios from 'axios'\n",
    "front/utils.js": "export function helper() {}\n",
}


def test_internal_imports_are_resolved_to_files():
    result = skeleton.build(PROJECT)

    assert "app/models.py" in result.imports_graph["app/main.py"]
    assert "app/services.py" in result.imports_graph["app/main.py"]


def test_relative_imports_are_resolved():
    """`from .services import run` inside app/main.py points at app/services.py."""
    result = skeleton.build(PROJECT)

    assert "app/services.py" in result.imports_graph["app/main.py"]


def test_javascript_relative_imports_are_resolved():
    result = skeleton.build(PROJECT)

    assert result.imports_graph["front/index.js"] == ["front/utils.js"]


def test_the_reverse_graph_says_who_imports_a_file():
    result = skeleton.build(PROJECT)

    assert set(result.imported_by["app/models.py"]) == {
        "app/main.py",
        "app/services.py",
    }


def test_third_party_packages_are_separated_from_the_standard_library():
    result = skeleton.build(PROJECT)

    assert "requests" in result.external_dependencies
    assert "axios" in result.external_dependencies
    # os is part of Python itself, not a dependency to install.
    assert "os" not in result.external_dependencies


def test_entry_points_are_listed():
    result = skeleton.build(PROJECT)

    assert "app/main.py" in result.entry_points
    assert "front/index.js" in result.entry_points
    assert "app/models.py" not in result.entry_points


def test_non_code_files_are_ignored_by_the_skeleton():
    result = skeleton.build({"README.md": "# hello", "app/main.py": "x = 1"})

    assert [file.path for file in result.files] == ["app/main.py"]


# ----------------------------------------------------------- reading order


def test_the_most_imported_file_comes_first():
    """Computed, not guessed: shared concepts live where imports converge."""
    order = skeleton.reading_order(skeleton.build(PROJECT))

    assert order[0] == "app/models.py"


def test_the_reading_order_is_bounded():
    order = skeleton.reading_order(skeleton.build(PROJECT), limit=3)

    assert len(order) == 3


# --------------------------------------------------------------------------
# Import roots: a repository does not say where Python's root is
# --------------------------------------------------------------------------


def test_internal_imports_resolve_when_the_code_sits_in_a_subfolder():
    """The bug a whole-repository fetch exposed.

    Uploading the backend folder gives 'analysis/x.py'; fetching the repo
    gives 'backend/analysis/x.py'. The same import must resolve in both, or
    every internal module is reported as a third-party dependency.
    """
    contents = {
        "backend/main.py": "from analysis import ingestion\nimport storage\n",
        "backend/analysis/ingestion.py": "def prepare():\n    pass\n",
        "backend/storage.py": "def save():\n    pass\n",
    }
    built = skeleton.build(contents)

    assert built.external_dependencies == []
    assert set(built.imports_graph["backend/main.py"]) == {
        "backend/analysis/ingestion.py",
        "backend/storage.py",
    }


def test_a_real_third_party_import_is_still_external():
    contents = {
        "backend/main.py": "from fastapi import FastAPI\nfrom analysis import x\n",
        "backend/analysis/x.py": "y = 1\n",
    }
    built = skeleton.build(contents)

    assert built.external_dependencies == ["fastapi"]


def test_an_ambiguous_short_name_is_left_unresolved_rather_than_guessed():
    """Two util.py in different packages: guessing would draw a false edge."""
    contents = {
        "app/main.py": "import util\n",
        "app/a/util.py": "x = 1\n",
        "app/b/util.py": "y = 2\n",
    }
    built = skeleton.build(contents)

    assert built.imports_graph["app/main.py"] == []
    assert "util" in built.external_dependencies


def test_a_full_path_beats_a_shortened_one():
    contents = {
        "main.py": "import config\n",
        "config.py": "AT_ROOT = True\n",
        "deep/nested/config.py": "NESTED = True\n",
    }
    built = skeleton.build(contents)

    assert built.imports_graph["main.py"] == ["config.py"]


def test_the_shallowest_module_wins_because_python_resolves_that_way():
    """`import notifications` with the root on the path finds the top-level
    module, not the one inside a package. The nested one is reachable only
    as `routers.notifications`.

    Found by reading the tool's own output on its own repository: both files
    exist, the name was treated as ambiguous, and `notifications` was
    reported to the user as a third-party dependency next to fastapi.
    """
    contents = {
        "main.py": "import notifications\n",
        "notifications.py": "def send():\n    pass\n",
        "routers/notifications.py": "def inbox():\n    pass\n",
    }
    built = skeleton.build(contents)

    assert built.imports_graph["main.py"] == ["notifications.py"]
    assert "notifications" not in built.external_dependencies


def test_the_nested_module_is_still_reachable_by_its_full_name():
    contents = {
        "main.py": "from routers import notifications\n",
        "notifications.py": "def send():\n    pass\n",
        "routers/notifications.py": "def inbox():\n    pass\n",
    }
    built = skeleton.build(contents)

    assert built.imports_graph["main.py"] == ["routers/notifications.py"]


def test_a_genuine_tie_at_the_same_depth_is_still_left_unresolved():
    """Two files equally deep give no reason to prefer either. An
    unresolved import is visible; a wrong edge in the graph is not."""
    contents = {
        "main.py": "import util\n",
        "a/util.py": "x = 1\n",
        "b/util.py": "y = 2\n",
    }
    built = skeleton.build(contents)

    assert built.imports_graph["main.py"] == []
    assert "util" in built.external_dependencies
