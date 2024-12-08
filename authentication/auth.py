from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
import jwt

class CustomJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # 인증이 필요 없는 경로 설정
        excluded_paths = ['/api/user/login/', '/api/user/register/', '/api/user/verify-email/']
        if request.path in excluded_paths:
            return None  # 인증 생략

        # Authorization 헤더에서 JWT 토큰 추출
        token = request.headers.get('Authorization')
        if not token:
            raise AuthenticationFailed('Authorization header missing')

        if token.startswith('Bearer '):
            token = token.split(' ')[1]  # "Bearer " 제거
        else:
            raise AuthenticationFailed('Invalid token format')

        # AccessToken 검증
        try:
            validated_token = AccessToken(token)
        except (TokenError, InvalidToken):
            raise AuthenticationFailed('Invalid or expired token')
        
        return (None, token)