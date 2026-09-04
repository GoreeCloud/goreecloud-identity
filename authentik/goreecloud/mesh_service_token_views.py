"""HTTP verification surface for GoreeCloud Mesh service credentials."""

from __future__ import annotations

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET
from structlog.stdlib import get_logger

from authentik.goreecloud.mesh_service_token import MeshServiceTokenIssuer

LOGGER = get_logger()


@require_GET
def mesh_service_token_jwks(request: HttpRequest) -> JsonResponse:
    """Publish Identity's public Mesh verification keys.

    This endpoint never issues credentials and never returns private key
    material. Missing or invalid runtime key configuration fails closed.
    """

    try:
        issuer = MeshServiceTokenIssuer.from_environment()
        response = JsonResponse(issuer.jwks())
    except (OSError, TypeError, ValueError) as exc:
        LOGGER.error(
            "GoreeCloud Mesh JWKS unavailable",
            error_type=type(exc).__name__,
        )
        response = JsonResponse(
            {"error": "goreecloud_mesh_jwks_unavailable"},
            status=503,
        )
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response

    response["Cache-Control"] = "public, max-age=60, must-revalidate"
    response["X-Content-Type-Options"] = "nosniff"
    return response
