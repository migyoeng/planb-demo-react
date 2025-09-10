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
    """사용자 정보 조회 - 간소화된 인증"""
    try:
        # request.user가 이미 인증된 경우 (Django REST Framework 인증)
        if hasattr(request, 'user') and request.user.is_authenticated:
            print(f"[USER INFO] 인증된 사용자: {request.user.username}")
            return Response(UserSerializer(request.user).data)
        
        # Fallback: 직접 토큰 검증 (간소화)
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({
                'error': '토큰이 필요합니다.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(' ')[1]
        
        # 간단한 JWT 디코딩 (서명 검증 생략)
        try:
            import jwt
            payload = jwt.decode(token, options={"verify_signature": False})
            username = payload.get('cognito:username') or payload.get('username')
            
            if not username:
                return Response({
                    'error': '사용자명을 찾을 수 없습니다.'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Django 사용자 조회
            user = User.objects.get(username=username)
            print(f"[USER INFO] 사용자 조회 성공: {user.username}")
            return Response(UserSerializer(user).data)
            
        except Exception as jwt_error:
            print(f"[USER INFO] JWT 디코딩 실패: {jwt_error}")
            return Response({
                'error': '토큰 검증 실패'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
    except User.DoesNotExist:
        return Response({
            'error': '사용자를 찾을 수 없습니다.'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print(f"[USER INFO] 예상치 못한 오류: {e}")
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
        
        # 0단계: Event 서비스에서 사용자 데이터 삭제
        event_delete_success = False
        event_delete_message = ""
        
        try:
            import requests
            from django.conf import settings
            
            # Event 서비스 URL 구성 (환경변수에서 가져오거나 기본값 사용)
            event_service_url = getattr(settings, 'EVENT_SERVICE_URL', 'https://42z6qi4fnd.execute-api.ap-northeast-2.amazonaws.com/prod')
            event_delete_url = f"{event_service_url}/api/event/delete-user-data/"
            
            # Event 서비스에 사용자 데이터 삭제 요청
            event_response = requests.delete(
                event_delete_url,
                json={'user_id': username},
                timeout=10
            )
            
            if event_response.status_code == 200:
                event_data = event_response.json()
                event_delete_success = True
                event_delete_message = f"Event 데이터 삭제 성공 - 예측: {event_data.get('deleted_predictions', 0)}개, 쿠폰: {event_data.get('deleted_coupons', 0)}개"
                print(f"[DELETE DEBUG] Event 서비스 데이터 삭제 성공: {event_delete_message}")
            else:
                event_delete_message = f"Event 서비스 삭제 실패: {event_response.status_code} - {event_response.text}"
                print(f"[DELETE DEBUG] Event 서비스 데이터 삭제 실패: {event_delete_message}")
                
        except Exception as e:
            event_delete_message = f"Event 서비스 연결 실패: {str(e)}"
            print(f"[DELETE DEBUG] Event 서비스 연결 오류: {str(e)}")
        
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
                    'event_status': event_delete_message,
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
                    'event_status': event_delete_message,
                    'cognito_status': cognito_message,
                    'django_status': django_message,
                    'deleted_user_id': user_id
                }
            }, status=status.HTTP_206_PARTIAL_CONTENT)
        
        elif cognito_success and not django_success:
            return Response({
                'error': 'Cognito는 삭제되었지만 Django 삭제에 실패했습니다.',
                'details': {
                    'event_status': event_delete_message,
                    'cognito_status': cognito_message,
                    'django_status': django_message
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        else:
            return Response({
                'error': '계정 삭제에 실패했습니다.',
                'details': {
                    'event_status': event_delete_message,
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
        
        # 간단한 JWT 디코딩 (서명 검증 생략)
        try:
            import jwt
            payload = jwt.decode(token, options={"verify_signature": False})
            username = payload.get('cognito:username') or payload.get('username')
            
            if not username:
                return Response({
                    'error': '사용자명을 찾을 수 없습니다.'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
        except Exception as jwt_error:
            print(f"[USER EVENTS] JWT 디코딩 실패: {jwt_error}")
            return Response({
                'error': '토큰 검증 실패'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        print(f"[USER EVENTS] 사용자 이벤트 참여내역 조회 - username: {username}")
        
        # Django 사용자 조회
        try:
            user = User.objects.get(username=username)
            print(f"[USER EVENTS] 사용자 조회 성공 - user.idx: {user.idx}, user.username: {user.username}")
        except User.DoesNotExist:
            print(f"[USER EVENTS] 사용자를 찾을 수 없음 - username: {username}")
            return Response({
                'error': '사용자를 찾을 수 없습니다.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Django ORM으로 복제된 테이블에 접근
        try:
            from django.db import connection
            
            print(f"[USER EVENTS] Django ORM으로 event 테이블 조회 시작 - username: {user.username}")
            
            with connection.cursor() as cursor:
                # 사용자 예측 내역 조회 (모든 데이터)
                cursor.execute("""
                    SELECT 
                        p.idx as predict_id,
                        p.user_id,
                        p.predicted,
                        p.created_at as predict_created_at,
                        s.idx as schedule_id,
                        s.match_date,
                        s.startTime,
                        s.homeTeamName,
                        s.awayTeamName,
                        s.homeResult,
                        s.awayResult,
                        s.gameStatus
                    FROM event_predict p
                    LEFT JOIN event_schedule s ON p.schedule_id = s.idx
                    WHERE p.user_id = %s
                    ORDER BY s.match_date DESC, p.created_at DESC
                    LIMIT 20
                """, [user.username])
                
                columns = [col[0] for col in cursor.description]
                predictions = [dict(zip(columns, row)) for row in cursor.fetchall()]
                print(f"[USER EVENTS] 예측 내역 조회 결과 - 개수: {len(predictions)}")
                if predictions:
                    print(f"[USER EVENTS] 첫 번째 예측 데이터: {predictions[0]}")
                    for i, pred in enumerate(predictions):
                        print(f"[USER EVENTS] 예측 {i+1}: match_date={pred.get('match_date')}, gameStatus='{pred.get('gameStatus')}', homeResult={pred.get('homeResult')}, awayResult={pred.get('awayResult')}")
                
                # 해당 사용자의 모든 예측 데이터 확인
                cursor.execute("""
                    SELECT 
                        p.idx as predict_id,
                        p.user_id,
                        p.predicted,
                        p.created_at,
                        s.match_date,
                        s.homeTeamName,
                        s.awayTeamName
                    FROM event_predict p
                    LEFT JOIN event_schedule s ON p.schedule_id = s.idx
                    WHERE p.user_id = %s
                    ORDER BY p.created_at DESC
                """, [user.username])
                
                all_predictions_columns = [col[0] for col in cursor.description]
                all_predictions_data = [dict(zip(all_predictions_columns, row)) for row in cursor.fetchall()]
                print(f"[USER EVENTS] 사용자 {user.username}의 모든 예측 데이터: {all_predictions_data}")
                
                # 통계 계산
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_predictions,
                        SUM(CASE WHEN p.predicted = CONCAT(s.homeResult, ':', s.awayResult) THEN 1 ELSE 0 END) as correct_predictions
                    FROM event_predict p
                    LEFT JOIN event_schedule s ON p.schedule_id = s.idx
                    WHERE p.user_id = %s AND s.gameStatus = 'END'
                """, [user.username])
                
                stats_columns = [col[0] for col in cursor.description]
                stats_row = cursor.fetchone()
                stats = dict(zip(stats_columns, stats_row)) if stats_row else {}
                total_predictions = stats.get('total_predictions', 0) or 0
                correct_predictions = stats.get('correct_predictions', 0) or 0
                accuracy = (correct_predictions / total_predictions * 100) if total_predictions > 0 else 0
                
        except Exception as db_error:
            print(f"[USER EVENTS] 데이터베이스 조회 실패: {db_error}")
            # DB 조회 실패 시 빈 데이터 반환
            predictions = []
            total_predictions = 0
            correct_predictions = 0
            accuracy = 0
        
        # 페이지네이션 정보
        page_size = 5
        total_count = len(predictions)
        total_pages = (total_count + page_size - 1) // page_size
        current_page = 1
        
        # React에서 예상하는 데이터 구조로 변환
        formatted_events = []
        for prediction in predictions:
            # 예측 결과 분석
            predicted_winner = None
            is_correct = None
            
            print(f"[USER EVENTS] 처리 중: gameStatus='{prediction['gameStatus']}', homeResult={prediction['homeResult']}, awayResult={prediction['awayResult']}")
            
            if prediction['gameStatus'] == 'END' and prediction['homeResult'] is not None and prediction['awayResult'] is not None:
                # 경기가 종료된 경우 정답 여부 판단
                if prediction['predicted'] == f"{prediction['homeResult']}:{prediction['awayResult']}":
                    is_correct = True
                else:
                    is_correct = False
                print(f"[USER EVENTS] END 경기 처리: is_correct={is_correct}")
            elif prediction['gameStatus'] == 'BEFORE':
                # 경기 전인 경우
                is_correct = None
                print(f"[USER EVENTS] BEFORE 경기 처리: is_correct={is_correct}")
            else:
                print(f"[USER EVENTS] 기타 상태: gameStatus='{prediction['gameStatus']}', is_correct={is_correct}")
            
            formatted_events.append({
                'predict_id': prediction['predict_id'],
                'user_id': prediction['user_id'],
                'predicted': prediction['predicted'],
                'predict_created_at': prediction['predict_created_at'],
                'schedule': {
                    'schedule_id': prediction['schedule_id'],
                    'match_date': prediction['match_date'],
                    'startTime': prediction['startTime'],
                    'homeTeamName': prediction['homeTeamName'],
                    'awayTeamName': prediction['awayTeamName'],
                    'homeResult': prediction['homeResult'],
                    'awayResult': prediction['awayResult'],
                    'gameStatus': prediction['gameStatus'],
                    # React에서 사용하는 필드명으로 매핑
                    'home_team': prediction['homeTeamName'],
                    'away_team': prediction['awayTeamName'],
                    'game_date': prediction['match_date']
                },
                'predicted_winner': predicted_winner,
                'is_correct': is_correct
            })

        return Response({
            'message': '이벤트 참여내역 조회 성공',
            'user_info': {
                'username': username,
                'user_id': user.idx
            },
            'events': formatted_events,
            'statistics': {
                'total_predictions': total_predictions,
                'correct_predictions': correct_predictions,
                'accuracy': round(accuracy, 2)
            },
            'pagination': {
                'current_page': current_page,
                'total_pages': total_pages,
                'total_count': total_count,
                'page_size': page_size,
                'has_next': current_page < total_pages,
                'has_previous': current_page > 1
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
        
        # 간단한 JWT 디코딩 (서명 검증 생략)
        try:
            import jwt
            payload = jwt.decode(token, options={"verify_signature": False})
            username = payload.get('cognito:username') or payload.get('username')
            
            if not username:
                return Response({
                    'error': '사용자명을 찾을 수 없습니다.'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
        except Exception as jwt_error:
            print(f"[USER COUPONS] JWT 디코딩 실패: {jwt_error}")
            return Response({
                'error': '토큰 검증 실패'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        print(f"[USER COUPONS] 사용자 쿠폰 현황 조회 - username: {username}")
        
        # Django 사용자 조회
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({
                'error': '사용자를 찾을 수 없습니다.'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Django ORM으로 복제된 테이블에 접근
        try:
            from django.db import connection
            
            print(f"[USER COUPONS] Django ORM으로 event 테이블 조회 시작")
            
            with connection.cursor() as cursor:
                # 사용자 쿠폰 조회
                cursor.execute("""
                    SELECT 
                        c.idx as coupon_id,
                        c.code as coupon_code,
                        c.coupon_status,
                        c.created_at,
                        c.updated_at,
                        c.expire_at,
                        p.user_id,
                        p.predicted,
                        s.match_date,
                        s.homeTeamName,
                        s.awayTeamName
                    FROM event_coupon c
                    LEFT JOIN event_predict p ON c.predict_id = p.idx
                    LEFT JOIN event_schedule s ON p.schedule_id = s.idx
                    WHERE p.user_id = %s
                    ORDER BY c.created_at DESC
                """, [user.username])
                
                columns = [col[0] for col in cursor.description]
                coupons = [dict(zip(columns, row)) for row in cursor.fetchall()]
                print(f"[USER COUPONS] 쿠폰 조회 결과 - 개수: {len(coupons)}")
                
                # 통계 계산
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_coupons,
                        SUM(CASE WHEN c.coupon_status = 2 THEN 1 ELSE 0 END) as available_coupons,
                        SUM(CASE WHEN c.coupon_status = 1 THEN 1 ELSE 0 END) as used_coupons,
                        SUM(CASE WHEN c.coupon_status = 0 THEN 1 ELSE 0 END) as expired_coupons
                    FROM event_coupon c
                    LEFT JOIN event_predict p ON c.predict_id = p.idx
                    WHERE p.user_id = %s
                """, [user.username])
                
                stats_columns = [col[0] for col in cursor.description]
                stats_row = cursor.fetchone()
                stats = dict(zip(stats_columns, stats_row)) if stats_row else {}
                total_coupons = stats.get('total_coupons', 0) or 0
                available_coupons = stats.get('available_coupons', 0) or 0
                used_coupons = stats.get('used_coupons', 0) or 0
                expired_coupons = stats.get('expired_coupons', 0) or 0
                
        except Exception as db_error:
            print(f"[USER COUPONS] 데이터베이스 조회 실패: {db_error}")
            # DB 조회 실패 시 빈 데이터 반환
            coupons = []
            total_coupons = 0
            available_coupons = 0
            used_coupons = 0
            expired_coupons = 0
        
        # React에서 예상하는 데이터 구조로 변환
        formatted_coupons = []
        for coupon in coupons:
            # 쿠폰 상태를 React가 기대하는 형태로 변환
            status_class = 'available'
            status_text = '사용가능'
            
            if coupon['coupon_status'] == 1:
                status_class = 'used'
                status_text = '사용완료'
            elif coupon['coupon_status'] == 0:
                status_class = 'expired'
                status_text = '기간만료'
            
            formatted_coupons.append({
                'coupon_id': coupon['coupon_id'],
                'coupon_code': coupon['coupon_code'],
                'coupon_name': f"경기예측 쿠폰 {coupon['coupon_code']}",  # React가 기대하는 필드
                'discount_amount': 1000,  # React가 기대하는 필드 (고정값)
                'status': status_text,  # React가 기대하는 필드
                'status_class': status_class,  # React가 기대하는 필드 (CSS 클래스용)
                'created_at': coupon['created_at'],
                'updated_at': coupon['updated_at'],
                'expires_at': coupon['expire_at'],  # React가 기대하는 필드명
                'used_at': coupon['updated_at'] if coupon['coupon_status'] == 1 else None,
                'match_info': {
                    'home_team': coupon['homeTeamName'],
                    'away_team': coupon['awayTeamName'],
                    'match_date': coupon['match_date'],
                    'predicted': coupon['predicted']
                }
            })

        return Response({
            'message': '쿠폰 현황 조회 성공',
            'user_info': {
                'username': username,
                'user_id': user.idx
            },
            'coupons': formatted_coupons,
            'statistics': {
                'total_coupons': total_coupons,
                'available_coupons': available_coupons,
                'used_coupons': used_coupons,
                'expired_coupons': expired_coupons
            }
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        print(f"[USER COUPONS] 예상치 못한 오류: {str(e)}")
        return Response({
            'error': f'쿠폰 현황 조회 중 오류 발생: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
