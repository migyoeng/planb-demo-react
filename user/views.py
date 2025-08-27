from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from .serializers import UserSerializer
from .models import User
from .cognito_auth import decode_cognito_jwt

@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    """Cognito 회원가입 - React에서 Cognito와 통신하므로 여기서는 성공 응답만"""
    return Response({
        'message': '회원가입은 React에서 Cognito를 통해 처리됩니다.',
        'status': 'success'
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """Cognito 로그인 - React에서 Cognito와 통신하므로 여기서는 성공 응답만"""
    return Response({
        'message': '로그인은 React에서 Cognito를 통해 처리됩니다.',
        'status': 'success'
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def confirm_registration(request):
    """Cognito 이메일 인증 - React에서 Cognito와 통신하므로 여기서는 성공 응답만"""
    return Response({
        'message': '이메일 인증은 React에서 Cognito를 통해 처리됩니다.',
        'status': 'success'
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_info(request):
    """사용자 정보 조회 - Cognito JWT로 인증"""
    try:
        # Cognito JWT 토큰에서 사용자 정보 추출
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({
                'error': '토큰이 필요합니다.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(' ')[1]
        
        # Cognito JWT 토큰 검증
        payload = decode_cognito_jwt(token)
        username = payload.get('cognito:username')
        
        if not username:
            return Response({
                'error': '사용자명을 찾을 수 없습니다.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Django 사용자 조회
        user = User.objects.get(username=username)
        return Response(UserSerializer(user).data)
        
    except User.DoesNotExist:
        return Response({
            'error': '사용자를 찾을 수 없습니다.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': f'사용자 정보 조회 실패: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user_info(request):
    """사용자 정보 업데이트 - Cognito JWT로 인증"""
    try:
        # Cognito JWT 토큰에서 사용자 정보 추출
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({
                'error': '토큰이 필요합니다.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(' ')[1]
        
        # Cognito JWT 토큰 검증
        payload = decode_cognito_jwt(token)
        username = payload.get('cognito:username')
        
        if not username:
            return Response({
                'error': '사용자명을 찾을 수 없습니다.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Django 사용자 조회
        user = User.objects.get(username=username)
        
        # 업데이트할 필드들
        update_fields = ['name', 'email', 'tel', 'birth', 'team']
        
        for field in update_fields:
            if field in request.data:
                setattr(user, field, request.data[field])
        
        # 변경사항 저장
        user.save()
        
        return Response({
            'message': '사용자 정보가 성공적으로 업데이트되었습니다.',
            'user': UserSerializer(user).data
        })
        
    except User.DoesNotExist:
        return Response({
            'error': '사용자를 찾을 수 없습니다.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            'error': f'사용자 정보 업데이트 실패: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)