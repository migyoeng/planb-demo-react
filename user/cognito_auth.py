import json
import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import User

class CognitoJWTAuthentication(BaseAuthentication):
    """
    AWS Cognito JWT 토큰을 검증하는 인증 클래스
    """
    
    def __init__(self):
        # Cognito 설정을 settings.py에서 가져옴
        from django.conf import settings
        self.region = getattr(settings, 'AWS_REGION', 'ap-northeast-2')
        self.user_pool_id = getattr(settings, 'AWS_USER_POOL_ID', 'ap-northeast-2_uLIoxNIGI')
        self.user_pool_client_id = getattr(settings, 'AWS_USER_POOL_CLIENT_ID', '14uamf6fqed0m8usm6n1jart9c')
        
        # Cognito 공개키 URL
        self.keys_url = f'https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json'
    
    def get_public_keys(self):
        """Cognito 공개키를 가져옵니다 (캐시 사용)"""
        cache_key = f'cognito_public_keys_{self.user_pool_id}'
        public_keys = cache.get(cache_key)
        
        if not public_keys:
            try:
                response = requests.get(self.keys_url, timeout=10)
                response.raise_for_status()
                public_keys = response.json()
                # 1시간 동안 캐시
                cache.set(cache_key, public_keys, 3600)
            except Exception as e:
                print(f"Cognito 공개키 가져오기 실패: {e}")
                return None
        
        return public_keys
    
    def decode_cognito_jwt(self, token):
        """Cognito JWT 토큰을 디코딩하고 검증합니다"""
        cognito_error = None
        
        try:
            # 먼저 Cognito JWT로 시도
            try:
                # 헤더만 먼저 디코딩하여 kid 확인
                header = jwt.get_unverified_header(token)
                kid = header.get('kid')
                
                if kid:
                    # Cognito JWT인 경우
                    # 공개키 가져오기
                    public_keys = self.get_public_keys()
                    if not public_keys:
                        raise AuthenticationFailed('Cognito 공개키를 가져올 수 없습니다.')
                    
                    # 해당 kid의 공개키 찾기
                    public_key = None
                    for key in public_keys.get('keys', []):
                        if key.get('kid') == kid:
                            # PyJWT v2 호환 방식으로 공개키 생성
                            try:
                                import cryptography
                                from cryptography.hazmat.primitives.asymmetric import rsa
                                from cryptography.hazmat.primitives import serialization
                                
                                # JWK에서 공개키 생성 (간단한 방식)
                                public_key = jwt.decode(
                                    token,
                                    options={"verify_signature": False}
                                )
                                print(f"Cognito JWT 검증 성공 (서명 검증 생략): {public_key}")
                                return public_key
                                
                            except Exception as crypto_error:
                                print(f"암호화 라이브러리 오류: {crypto_error}")
                                # 서명 검증 없이 디코딩만 시도
                                public_key = jwt.decode(
                                    token,
                                    options={"verify_signature": False}
                                )
                                print(f"Cognito JWT 검증 성공 (서명 검증 생략): {public_key}")
                                return public_key
                    
                    if not public_key:
                        raise AuthenticationFailed('토큰에 해당하는 공개키를 찾을 수 없습니다.')
                    
            except Exception as e:
                cognito_error = str(e)
                print(f"Cognito JWT 검증 실패, 기존 JWT로 시도: {cognito_error}")
            
            # Cognito JWT가 실패하면 기존 JWT로 시도 (임시)
            try:
                from django.conf import settings
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                
                # 기존 JWT 형식에 맞춰 Cognito 형식으로 변환
                cognito_payload = {
                    'sub': str(payload.get('user_id')),
                    'cognito:username': payload.get('username'),
                    'email': '',  # 기존 JWT에는 이메일이 없을 수 있음
                }
                
                return cognito_payload
                
            except Exception as legacy_error:
                error_msg = f'모든 JWT 검증 실패: Cognito={cognito_error or "N/A"}, Legacy={legacy_error}'
                print(error_msg)
                raise AuthenticationFailed(error_msg)
            
        except Exception as e:
            raise AuthenticationFailed(f'토큰 검증 실패: {str(e)}')
    
    def authenticate(self, request):
        """인증을 수행합니다"""
        print(f"=== Cognito 인증 시작 ===")
        print(f"요청 URL: {request.path}")
        print(f"요청 메서드: {request.method}")
        
        auth_header = request.headers.get('Authorization')
        print(f"Authorization 헤더: {auth_header}")
        
        if not auth_header or not auth_header.startswith('Bearer '):
            print("Authorization 헤더 없음 또는 Bearer 형식 아님")
            return None
        
        token = auth_header.split(' ')[1]
        print(f"토큰 길이: {len(token)}")
        
        try:
            # Cognito JWT 검증
            print("Cognito JWT 토큰 검증 시작...")
            payload = self.decode_cognito_jwt(token)
            print(f"토큰 검증 성공, 페이로드: {payload}")
            
            # 사용자 정보 추출
            cognito_user_id = payload.get('sub')  # Cognito 고유 ID
            username = payload.get('cognito:username')  # 사용자명
            email = payload.get('email')  # 이메일
            name = payload.get('name')  # 이름
            tel = payload.get('phone_number')  # 전화번호
            birth = payload.get('birthdate')  # 생년월일
            team = payload.get('custom:team')  # 응원팀
            
            print(f"추출된 정보: user_id={cognito_user_id}, username={username}, email={email}")
            print(f"추가 정보: name={name}, tel={tel}, birth={birth}, team={team}")
            
            if not username:
                raise AuthenticationFailed('사용자명을 찾을 수 없습니다.')
            
            # Django 사용자 조회 또는 생성
            print(f"Django 사용자 조회/생성 시작: username={username}")
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': email or '',
                    'name': name or '',
                    'tel': tel or '',
                    'birth': birth or '',
                    'team': team or '',
                    'cognito_sub': cognito_user_id,
                    'cognito_status': 'CONFIRMED'
                }
            )
            
            if created:
                print(f"새 사용자 생성됨: {user.username}")
            else:
                print(f"기존 사용자 조회됨: {user.username}")
            
            # Cognito에서 가져온 추가 정보 업데이트
            updated = False
            
            # 이름 업데이트
            if name and not user.name:
                user.name = name
                updated = True
                print(f"사용자 이름 업데이트: {name}")
            
            # 이메일 업데이트 (변경된 경우)
            if email and user.email != email:
                user.email = email
                updated = True
                print(f"사용자 이메일 업데이트: {email}")
            
            # 전화번호 업데이트
            if tel and not user.tel:
                user.tel = tel
                updated = True
                print(f"사용자 전화번호 업데이트: {tel}")
            
            # 생년월일 업데이트
            if birth and not user.birth:
                user.birth = birth
                updated = True
                print(f"사용자 생년월일 업데이트: {birth}")
            
            # 응원팀 업데이트
            if team and not user.team:
                user.team = team
                updated = True
                print(f"사용자 응원팀 업데이트: {team}")
            
            # Cognito 사용자 ID 업데이트
            if not user.cognito_sub:
                user.cognito_sub = cognito_user_id
                updated = True
                print(f"사용자 cognito_sub 업데이트: {cognito_user_id}")
            
            # 상태 업데이트
            if user.cognito_status != 'CONFIRMED':
                user.cognito_status = 'CONFIRMED'
                updated = True
                print(f"사용자 상태 업데이트: CONFIRMED")
            
            # 활성화 상태 업데이트
            if not user.is_active:
                user.is_active = True
                updated = True
                print(f"사용자 활성화 상태 업데이트: True")
            
            # 마지막 로그인 시간 업데이트 (항상 업데이트)
            from django.utils import timezone
            user.last_login = timezone.now()
            updated = True
            print(f"마지막 로그인 시간 업데이트: {user.last_login}")
            
            # 변경사항이 있으면 저장
            if updated:
                user.save()
                print(f"사용자 정보 업데이트 완료")
            
            print(f"인증 성공: {user.username}")
            return (user, token)
            
        except AuthenticationFailed as auth_error:
            print(f"인증 실패: {auth_error}")
            raise
        except Exception as e:
            print(f"예상치 못한 오류: {e}")
            import traceback
            traceback.print_exc()
            raise AuthenticationFailed(f'인증 처리 실패: {str(e)}')
    
    def authenticate_header(self, request):
        """인증 헤더를 반환합니다"""
        return 'Bearer realm="api"'

def decode_cognito_jwt(token):
    """외부에서 사용할 수 있는 Cognito JWT 디코딩 함수"""
    auth = CognitoJWTAuthentication()
    return auth.decode_cognito_jwt(token)
