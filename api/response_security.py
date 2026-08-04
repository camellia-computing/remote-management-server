CREDENTIAL_RESPONSE_MARKER = "_camellia_credential_response"


def credential_response(view):
    """Mark every response from a credential route as non-cacheable."""

    setattr(view, CREDENTIAL_RESPONSE_MARKER, True)
    return view


def protect_credential_response(response):
    """Apply the same fail-closed cache policy to successes and errors."""

    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    response["Referrer-Policy"] = "no-referrer"
    return response
