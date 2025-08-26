import random
import string
import jwt
import datetime
from django.conf import settings
from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from .serializers import SignupSerializer, LoginSerializer, ConfirmSerializer, UserSerializer
from .models import User, EmailVerification

def generate_verification_code():
    """6자리 인증 코드 생성"""
    return ''.join(random.choices(string.digits, k=6))

def generate_jwt_token(user):
    """JWT 토큰 생성"""
    payload = {
        'user_id': user.idx,
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
        'iat': datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    """회원가입"""
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        try:
            # 사용자명 중복 확인
            if User.objects.filter(username=serializer.validated_data['username']).exists():
                return Response({
                    'error': '이미 사용 중인 사용자명입니다.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # 이메일 중복 확인
            if User.objects.filter(email=serializer.validated_data['email']).exists():
                return Response({
                    'error': '이미 사용 중인 이메일입니다.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Django 사용자 생성 (새로운 DB 스키마에 맞춤)
            user_data = serializer.validated_data.copy()
            password = user_data.pop('password')
            
            user = User.objects.create_user(
                username=user_data['username'],
                email=user_data['email'],
                password=password,
                tel=user_data.get('tel', ''),
                birth=user_data.get('birth', ''),
                team=user_data.get('team', ''),
                name=user_data.get('name', ''),
                cognito_status='UNCONFIRMED'
            )
            
            # 인증 코드 생성 (24시간 유효)
            code = generate_verification_code()
            expires_at = timezone.now() + timezone.timedelta(hours=24)
            
            EmailVerification.objects.create(
                user=user,
                code=code,
                expires_at=expires_at
            )
            
            # 실제로는 여기서 이메일 발송 로직 구현
            # 현재는 콘솔에 출력
            print(f"사용자 {user.username}에게 인증 코드 {code} 발송")
            
            return Response({
                'message': '회원가입이 완료되었습니다. 이메일 인증을 진행해주세요.',
                'verification_code': code,  # 테스트용 (실제로는 이메일로 발송)
                'user_id': user.idx
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'error': f'회원가입 실패: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """로그인"""
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        try:
            # Django 기본 인증 시스템 사용
            user = authenticate(username=username, password=password)
            
            if user is not None:
                if user.is_active:
                    # 마지막 로그인 시간 업데이트
                    user.last_login = timezone.now()
                    user.save()
                    
                    # JWT 토큰 생성
                    token = generate_jwt_token(user)
                    
                    return Response({
                        'access_token': token,
                        'user': UserSerializer(user).data,
                        'message': '로그인 성공'
                    })
                else:
                    return Response({
                        'error': '비활성화된 계정입니다.'
                    }, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    'error': '사용자명 또는 비밀번호가 올바르지 않습니다.'
                }, status=status.HTTP_401_UNAUTHORIZED)
                
        except Exception as e:
            return Response({
                'error': f'로그인 실패: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def confirm_registration(request):
    """이메일 인증 확인"""
    serializer = ConfirmSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        code = serializer.validated_data['code']
        
        try:
            user = User.objects.get(username=username)
            
            # 인증 코드 확인
            verification = EmailVerification.objects.filter(
                user=user,
                code=code,
                is_used=False
            ).first()
            
            if not verification:
                return Response({
                    'error': '잘못된 인증 코드입니다.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if verification.is_expired():
                return Response({
                    'error': '인증 코드가 만료되었습니다.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # 인증 완료 처리
            verification.is_used = True
            verification.save()
            
            # 사용자 상태를 CONFIRMED로 변경
            user.cognito_status = 'CONFIRMED'
            user.save()
            
            return Response({
                'message': '이메일 인증이 완료되었습니다.'
            })
            
        except User.DoesNotExist:
            return Response({
                'error': '사용자를 찾을 수 없습니다.'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': f'인증 실패: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """로그아웃"""
    return Response({
        'message': '로그아웃되었습니다.'
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_token(request):
    """토큰 검증 및 사용자 정보 반환"""
    # JWT 토큰에서 사용자 ID 추출
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
            user = User.objects.get(idx=user_id)
            return Response(UserSerializer(user).data)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({
                'error': '유효하지 않은 토큰입니다.'
            }, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response({
        'error': '토큰이 필요합니다.'
    }, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_info(request):
    """사용자 정보 조회"""
    # JWT 토큰에서 사용자 ID 추출
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
            user = User.objects.get(idx=user_id)
            return Response(UserSerializer(user).data)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({
                'error': '유효하지 않은 토큰입니다.'
            }, status=status.HTTP_401_UNAUTHORIZED)
    
    return Response({
        'error': '토큰이 필요합니다.'
    }, status=status.HTTP_401_UNAUTHORIZED)