SENSITIVE_RESPONSE_MARKER = "_camellia_sensitive_response"
# Keep the credential-specific name as a source-compatible alias for callers
# introduced before the policy was extended to authenticated browser routes.
CREDENTIAL_RESPONSE_MARKER = SENSITIVE_RESPONSE_MARKER


def sensitive_response(view):
    """Mark every response from a sensitive route as non-cacheable."""

    setattr(view, SENSITIVE_RESPONSE_MARKER, True)
    return view


def protect_sensitive_response(response):
    """Apply the same fail-closed cache policy to successes and errors."""

    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    response["Expires"] = "0"
    response["Referrer-Policy"] = "no-referrer"
    return response


credential_response = sensitive_response
protect_credential_response = protect_sensitive_response
