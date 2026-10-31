import os
import sys

_test_dir = os.path.dirname(os.path.abspath(__file__))
_integration_dir = os.path.dirname(_test_dir)
_core_dir = os.path.join(_integration_dir, "core")

for p in [_integration_dir, _core_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)
