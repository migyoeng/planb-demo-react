#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from django.core.management import execute_from_command_line


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'demo_user.settings')
    try:
        from django.conf import settings
        port = getattr(settings, 'PORT', 8000)
        
        # runserver 명령어에 포트 자동 추가
        if len(sys.argv) >= 2 and sys.argv[1] == 'runserver':
            if len(sys.argv) == 2:  # runserver만 입력한 경우
                sys.argv.append(f'127.0.0.1:{port}')
            elif len(sys.argv) == 3 and ':' not in sys.argv[2]:  # runserver 8000 같은 경우
                sys.argv[2] = f'127.0.0.1:{port}'
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
