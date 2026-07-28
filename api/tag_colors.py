import re


MAX_ARGB_COLOR = 0xFFFFFFFF


def normalize_tag_color(value):
    """Return the client's canonical unsigned ARGB decimal representation."""

    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        value = value.strip()
        if re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
            number = int(f"FF{value[1:]}", 16)
        elif re.fullmatch(r"#[0-9A-Fa-f]{8}", value):
            number = int(value[1:], 16)
        elif value.isascii() and value.isdigit():
            number = int(value)
        else:
            return None
    else:
        return None
    return str(number) if 0 <= number <= MAX_ARGB_COLOR else None


def tag_color_css(value):
    normalized = normalize_tag_color(value)
    if not normalized:
        return "#94a3b8"
    return f"#{int(normalized) & 0xFFFFFF:06x}"
