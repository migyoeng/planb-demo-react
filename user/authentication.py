from rest_framework import authentication
from rest_framework import exceptions
from django.conf import settings
import jwt
from .models import User

class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            # "Bearer <token>" 형식에서 토큰 추출
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                return None

            # JWT 토큰 디코딩
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
            
            if not user_id:
                raise exceptions.AuthenticationFailed('유효하지 않은 토큰입니다.')

            # 사용자 조회
            try:
                user = User.objects.get(idx=user_id)
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed('사용자를 찾을 수 없습니다.')

            return (user, token)

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('토큰이 만료되었습니다.')
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed('유효하지 않은 토큰입니다.')
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'인증 실패: {str(e)}')

    def authenticate_header(self, request):
        return 'Bearer'
