# ===== 빌드 스테이지 =====
FROM python:3.11-slim AS builder

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 빌드 도구 설치
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/cache/apt/*

# Python 의존성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ===== 실행 스테이지 =====
FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /app

# 필요한 런타임 패키지만 설치 (빌드 도구 제외)
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    curl \
    dos2unix \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/cache/apt/*

# 빌드 스테이지에서 Python 패키지 복사
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# 프로젝트 파일 복사
COPY . .

# 정적 파일 수집
# RUN python manage.py collectstatic --noinput

# 로그 디렉토리 생성
RUN mkdir -p /var/log/django

# 포트 노출
EXPOSE 8001

# 환경 변수 설정
ENV PYTHONPATH=/app
ENV DJANGO_SETTINGS_MODULE=demo_user.settings
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# 헬스체크 추가
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import socket; socket.socket().connect(('localhost', 8001))" || exit 1

# 스크립트 파일 복사 및 줄바꿈 문자 변환
COPY ./entrypoint-migrate.sh /app/
COPY ./entrypoint-web.sh /app/

# Windows 줄바꿈 문자를 Unix 형식으로 변환하고 실행 권한 부여
RUN dos2unix /app/entrypoint-migrate.sh /app/entrypoint-web.sh && \
    chmod +x /app/entrypoint-migrate.sh /app/entrypoint-web.sh

# 기본 명령어 설정 -> Task Definition에서 override 가능
CMD ["/app/entrypoint-web.sh"]
