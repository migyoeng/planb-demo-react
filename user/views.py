from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from .serializers import UserSerializer
from .models import User
from .cognito_auth import decode_cognito_jwt
import boto3
from botocore.exceptions import ClientError
import requests

def delete_cognito_user(username):
    """Cognito User Pool에서 사용자 삭제"""
    try:
        # AWS 설정값들 - settings에서 가져오기
        AWS_REGION = settings.AWS_REGION
        USER_POOL_ID = settings.AWS_USER_POOL_ID
        
        print(f"[COGNITO DELETE] AWS 설정 - Region: {AWS_REGION}, UserPoolId: {USER_POOL_ID}")
        
        # Cognito Identity Provider 클라이언트 생성
        cognito_client = boto3.client('cognito-idp', region_name=AWS_REGION)
        
        print(f"[COGNITO DELETE] Cognito 사용자 삭제 시도 - username: {username}")
        
        # Admin 권한으로 사용자 삭제
        response = cognito_client.admin_delete_user(
            UserPoolId=USER_POOL_ID,
            Username=username
        )
        
        print(f"[COGNITO DELETE] Cognito 사용자 삭제 성공 - username: {username}")
        return True, "Cognito 사용자 삭제 성공"
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"[COGNITO DELETE] Cognito 사용자 삭제 실패 - {error_code}: {error_message}")
        
        if error_code == 'UserNotFoundException':
            return True, "사용자가 Cognito에 존재하지 않음 (이미 삭제됨)"
        else:
            return False, f"Cognito 삭제 실패: {error_message}"
            
    except Exception as e:
        print(f"[COGNITO DELETE] 예상치 못한 오류: {str(e)}")
        return False, f"Cognito 삭제 중 오류: {str(e)}"

@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    """Cognito 회원가입 - React에서 Cognito와 통신하므로 여기서는 성공 응답만"""
    try:
        print(f"[SIGNUP DEBUG] API 호출됨 - Method: {request.method}")
        print(f"[SIGNUP DEBUG] Headers: {dict(request.headers)}")
        print(f"[SIGNUP DEBUG] Request data: {request.data}")
        
        user_data = request.data
        
        # 필수 필드 확인
        required_fields = ['username', 'email']
        for field in required_fields:
            if not user_data.get(field):
                print(f"[SIGNUP DEBUG] 필수 필드 누락: {field}")
                return Response({
                    'error': f'필수 필드가 누락되었습니다: {field}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        print(f"[SIGNUP DEBUG] 사용자 생성 시도 - username: {user_data.get('username')}")
        
        # 사용자 생성 (password도 함께 저장)
        user = User.objects.create(
            username=user_data['username'],
            email=user_data['email'],
            password=make_password(user_data.get('password', '')),  # 비밀번호 암호화하여 저장
            cognito_sub=user_data.get('cognito_sub', ''),  # Cognito sub 값 저장
            name=user_data.get('name', user_data['username']),
            tel=user_data.get('tel', ''),
            birth=user_data.get('birth', ''),
            team=user_data.get('team', ''),
            cognito_status='UNCONFIRMED'
        )
        
        print(f"[SIGNUP DEBUG] 사용자 생성 성공 - ID: {user.idx}, username: {user.username}")
        
        return Response({
            'message': '회원가입이 완료되었습니다.',
            'status': 'success',
            'user_id': user.idx
        }, status=status.HTTP_201_CREATED)
    except Exception as e:
        print(f"[SIGNUP DEBUG] 회원가입 실패: {str(e)}")
        print(f"[SIGNUP DEBUG] Exception type: {type(e)}")
        return Response({
            'error': f'회원가입 실패: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user_account(request):
    """사용자 계정 삭제 - Django + Cognito 모두 삭제"""
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
        
        print(f"[DELETE DEBUG] 계정 삭제 요청 - username: {username}")
        
        # Django 사용자 조회
        try:
            user = User.objects.get(username=username)
            user_id = user.idx
            user_email = user.email
        except User.DoesNotExist:
            return Response({
                'error': '사용자를 찾을 수 없습니다.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # 1단계: Cognito에서 사용자 삭제 시도
        cognito_success, cognito_message = delete_cognito_user(username)
        
        # 2단계: Django에서 사용자 삭제
        django_success = False
        django_message = ""
        
        try:
            user.delete()  # CASCADE로 관련 데이터도 함께 삭제됨
            django_success = True
            django_message = "Django 사용자 삭제 성공"
            print(f"[DELETE DEBUG] Django 사용자 삭제 완료 - ID: {user_id}, Email: {user_email}")
        except Exception as e:
            django_message = f"Django 삭제 실패: {str(e)}"
            print(f"[DELETE DEBUG] Django 사용자 삭제 실패: {str(e)}")
        
        # 결과 분석 및 응답
        if cognito_success and django_success:
            return Response({
                'message': '계정이 완전히 삭제되었습니다.',
                'details': {
                    'cognito_status': cognito_message,
                    'django_status': django_message,
                    'deleted_user_id': user_id
                }
            }, status=status.HTTP_200_OK)
        
        elif django_success and not cognito_success:
            return Response({
                'message': 'Django에서는 삭제되었지만 Cognito 삭제에 실패했습니다.',
                'warning': 'Cognito 계정이 남아있을 수 있습니다.',
                'details': {
                    'cognito_status': cognito_message,
                    'django_status': django_message,
                    'deleted_user_id': user_id
                }
            }, status=status.HTTP_206_PARTIAL_CONTENT)
        
        elif cognito_success and not django_success:
            return Response({
                'error': 'Cognito는 삭제되었지만 Django 삭제에 실패했습니다.',
                'details': {
                    'cognito_status': cognito_message,
                    'django_status': django_message
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        else:
            return Response({
                'error': '계정 삭제에 실패했습니다.',
                'details': {
                    'cognito_status': cognito_message,
                    'django_status': django_message
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    except Exception as e:
        print(f"[DELETE DEBUG] 예상치 못한 오류: {str(e)}")
        return Response({
            'error': f'계정 삭제 중 오류 발생: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_events(request):
    """사용자 이벤트 참여내역 조회 - DMS 모델 구현 후 직접 DB 조회 예정"""
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
        
        print(f"[USER EVENTS] 사용자 이벤트 참여내역 조회 - username: {username}")
        
        # Django 사용자 조회
        try:
            user = User.objects.get(username=username)
            # event-msa에서는 username을 user_id로 사용하므로 username을 전송
            user_id = username  # user.idx 대신 username 사용
        except User.DoesNotExist:
            return Response({
                'error': '사용자를 찾을 수 없습니다.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # TODO: DMS 테이블 모델 생성 후 직접 DB 조회로 변경
        # 현재는 임시로 빈 데이터 반환
        print(f"[USER EVENTS] DMS 테이블 모델 미구현 - 임시 빈 데이터 반환")
        
        return Response({
            'message': '이벤트 참여내역 조회 (DMS 모델 구현 필요)',
            'user_info': {
                'username': username,
                'user_id': user_id
            },
            'events': [],
            'statistics': {
                'total_predictions': 0,
                'correct_predictions': 0,
                'accuracy': 0
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"[USER EVENTS] 예상치 못한 오류: {str(e)}")
        return Response({
            'error': f'이벤트 참여내역 조회 중 오류 발생: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_coupons(request):
    """사용자 보유 쿠폰 현황 조회 - DMS 모델 구현 후 직접 DB 조회 예정"""
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
        
        print(f"[USER COUPONS] 사용자 쿠폰 현황 조회 - username: {username}")
        
        # Django 사용자 조회
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({
                'error': '사용자를 찾을 수 없습니다.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # TODO: DMS 동기화 완료 후 활성화
        # from .models import EventCoupon, EventPredict, EventSchedule
        from django.utils import timezone
        
        # 임시로 빈 쿠폰 리스트 반환 (DMS 모델 구현 전)
        user_coupons = []
        
        coupons = []
        total_coupons = 0
        used_coupons = 0
        available_coupons = 0
        expired_coupons = 0
        
        now = timezone.now()
        
        for coupon in user_coupons:
            # 쿠폰 상태 판정
            is_used = coupon.used_at is not None
            if is_used:
                status_text = "사용완료"
                status_class = "used"
                used_coupons += 1
            elif coupon.expires_at < now:
                status_text = "기간만료"
                status_class = "expired"
                expired_coupons += 1
            else:
                status_text = "사용가능"
                status_class = "available"
                available_coupons += 1
            
            # 예측 정보 구성
            predict_info = None
            if coupon.predict and coupon.predict.schedule:
                predict_info = {
                    'game_date': coupon.predict.schedule.game_date.isoformat() if coupon.predict.schedule.game_date else None,
                    'home_team': coupon.predict.schedule.home_team_name or coupon.predict.schedule.home_team,
                    'away_team': coupon.predict.schedule.away_team_name or coupon.predict.schedule.away_team,
                    'predicted': coupon.predict.predicted_winner
                }
            
            coupon_data = {
                'coupon_id': coupon.id,
                'coupon_name': coupon.coupon_name,
                'coupon_type': coupon.coupon_type,
                'discount_amount': coupon.discount_amount,
                'status': status_text,
                'status_class': status_class,
                'is_used': is_used,
                'used_at': coupon.used_at.isoformat() if coupon.used_at else None,
                'expires_at': coupon.expires_at.isoformat(),
                'created_at': coupon.created_at.isoformat(),
                'predict_info': predict_info
            }
            coupons.append(coupon_data)
            total_coupons += 1
        
        # 통계 계산
        statistics = {
            'total_coupons': total_coupons,
            'available_coupons': available_coupons,
            'used_coupons': used_coupons,
            'expired_coupons': expired_coupons
        }
        
        print(f"[USER COUPONS] 조회 완료 - 총 {total_coupons}개, 사용가능 {available_coupons}개")
        
        return Response({
            'message': '쿠폰 현황 조회 성공',
            'user_info': {
                'username': username,
                'user_id': user.idx
            },
            'coupons': coupons,
            'statistics': statistics
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        print(f"[USER COUPONS] 예상치 못한 오류: {str(e)}")
        return Response({
            'error': f'쿠폰 현황 조회 중 오류 발생: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
