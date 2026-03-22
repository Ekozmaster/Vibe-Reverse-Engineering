import os
import pytest

@pytest.fixture
def sample_binary():
    candidates = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ntdll.dll"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    pytest.skip("No PE binary available for testing")
