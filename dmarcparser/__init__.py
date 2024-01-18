from . import _version
from .parser import DmarcParser, DmarcException

__version__: str = _version.version
__all__ = [
    "DmarcParser",
    "DmarcException",
    "__version__",
]
