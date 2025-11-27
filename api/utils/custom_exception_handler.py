import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is None:
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return Response({'detail': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    if response.status_code == status.HTTP_403_FORBIDDEN:
        response.data = {'detail': 'Authentication credentials were not provided.'}
        response.status_code = status.HTTP_401_UNAUTHORIZED
    elif response.status_code == status.HTTP_401_UNAUTHORIZED:
        response.data = {'detail': 'Authentication credentials were not provided.'}

    return response
