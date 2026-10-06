"""
packet_engine/redis/__init__.py
Bridge to PyPI redis library to prevent directory namespace collision and export FlowCache.
"""
import sys

_paths_to_strip = [p for p in sys.path if p in ("/app", ".", "", "/app/redis")]
for _p in _paths_to_strip:
    sys.path.remove(_p)

try:
    import redis as _pypi_redis
    for _name in dir(_pypi_redis):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_pypi_redis, _name)
finally:
    for _p in reversed(_paths_to_strip):
        sys.path.insert(0, _p)
