import importlib.metadata


def get_version() -> str:
    """Read version from package metadata."""
    try:
        return importlib.metadata.version("tplink-vx800v-exporter")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"
