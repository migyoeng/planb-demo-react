from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from user.models import User


class Command(BaseCommand):
    help = '간단한 관리자 계정 생성 (admin/Soldesk12!@)'

    def handle(self, *args, **options):
        username = 'admin'
        password = 'Soldesk12!@'
        email = 'admin@soldesk.com'
        name = '관리자'

        # 이미 존재하는지 확인
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'관리자 계정 "{username}"이 이미 존재합니다.')
            )
            return

        try:
            # 관리자 계정 생성
            admin_user = User.objects.create(
                username=username,
                email=email,
                password=make_password(password),
                name=name,
                cognito_sub='',  # 관리자는 Cognito 사용 안함
                cognito_status='ADMIN',
                is_superuser=True  # 관리자 권한
            )

            self.stdout.write(
                self.style.SUCCESS(
                    f'관리자 계정이 생성되었습니다!\n'
                    f'사용자명: {username}\n'
                    f'비밀번호: {password}\n'
                    f'이메일: {email}'
                )
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'관리자 계정 생성 실패: {str(e)}')
            )
