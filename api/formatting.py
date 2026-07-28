BYTE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")


def format_bytes(size_bytes):
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int):
        raise TypeError("size_bytes must be an integer")
    if size_bytes < 0:
        raise ValueError("size_bytes cannot be negative")
    value = float(size_bytes)
    unit = BYTE_UNITS[0]
    for unit in BYTE_UNITS:
        if value < 1024 or unit == BYTE_UNITS[-1]:
            break
        value /= 1024
    if unit == BYTE_UNITS[0]:
        return f"{size_bytes} {unit}"
    return f"{value:.2f}".rstrip("0").rstrip(".") + f" {unit}"
