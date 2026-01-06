#!/usr/bin/env python3
"""
Deep Guard 통합 분석 실행 스크립트
정적 분석 → 동적 분석 순차 실행
"""

import subprocess
import sys
import os
from pathlib import Path


def run_static_analysis(apk_path: str, test_mode: bool = False):
    """정적 분석 실행"""
    print("=" * 80)
    print("1. 정적 분석 시작")
    print("=" * 80)
    
    static_main = Path(__file__).parent / "static_analysis" / "src" / "main.py"
    
    if not static_main.exists():
        print(f"✗ 정적 분석 스크립트를 찾을 수 없습니다: {static_main}")
        return False
    
    cmd = ["python", str(static_main), apk_path]
    if test_mode:
        cmd.append("--test")
    
    print(f"실행: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, check=True)
        print()
        print("✓ 정적 분석 완료")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ 정적 분석 실패 (exit code: {e.returncode})")
        return False
    except Exception as e:
        print(f"✗ 정적 분석 실행 중 오류: {e}")
        return False


def run_dynamic_analysis():
    """동적 분석 실행 (Docker 컨테이너 내부)"""
    print()
    print("=" * 80)
    print("2. 동적 분석 시작")
    print("=" * 80)
    
    # 먼저 Docker 컨테이너에 필요한 패키지 설치
    print("2-1. Docker 컨테이너에 필요한 패키지 설치 중...")
    install_cmd = [
        "docker", "exec", "-u", "0", "mobsf3",
        "pip", "install", "python-dotenv", "frida"
    ]
    
    try:
        subprocess.run(install_cmd, check=True, capture_output=True, text=True)
        print("✓ 패키지 설치 완료")
    except subprocess.CalledProcessError as e:
        print(f"⚠ 패키지 설치 실패 (계속 진행): {e.stderr if e.stderr else ''}")
    except Exception as e:
        print(f"⚠ 패키지 설치 중 오류 (계속 진행): {e}")
    
    print()
    print("2-2. 동적 분석 실행 중...")
    cmd = [
        "docker", "exec", "-u", "0", "-it", "-w", "/Deepguard", "mobsf3",
        "python", "/Deepguard/deepguard_dynamic_analyzer.py"
    ]
    
    print(f"실행: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, check=True)
        print()
        print("✓ 동적 분석 완료")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ 동적 분석 실패 (exit code: {e.returncode})")
        return False
    except Exception as e:
        print(f"✗ 동적 분석 실행 중 오류: {e}")
        return False


def main():
    """메인 함수"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Deep Guard 통합 분석 도구 (정적 → 동적)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예제:
  # APK 전체 분석 (정적 + 동적)
  python run_analysis.py apk/sample.apk
  
  # 테스트 모드로 정적 분석 후 동적 분석
  python run_analysis.py apk/sample.apk --test
  
  # 정적 분석만 실행
  python run_analysis.py apk/sample.apk --static-only
  
  # 동적 분석만 실행
  python run_analysis.py --dynamic-only
        """
    )
    
    parser.add_argument('apk_path', nargs='?', help='APK 파일 경로 (동적 분석만 실행 시 생략 가능)')
    parser.add_argument('--test', action='store_true',
                       help='정적 분석 테스트 모드')
    parser.add_argument('--static-only', action='store_true',
                       help='정적 분석만 실행')
    parser.add_argument('--dynamic-only', action='store_true',
                       help='동적 분석만 실행')
    
    args = parser.parse_args()
    
    # 검증
    if not args.dynamic_only and not args.apk_path:
        parser.error("APK 경로를 지정해야 합니다 (--dynamic-only 옵션 사용 시 제외)")
    
    if args.static_only and args.dynamic_only:
        parser.error("--static-only와 --dynamic-only를 동시에 사용할 수 없습니다")
    
    success = True
    
    # 정적 분석 실행
    if not args.dynamic_only:
        if not run_static_analysis(args.apk_path, test_mode=args.test):
            success = False
            if not args.static_only:
                print()
                print("⚠ 정적 분석 실패로 동적 분석을 건너뜁니다")
                sys.exit(1)
    
    # 동적 분석 실행
    if not args.static_only and success:
        if not run_dynamic_analysis():
            success = False
    
    # 최종 결과
    print()
    print("=" * 80)
    if success:
        print("✓ 전체 분석 완료!")
    else:
        print("✗ 분석 실패")
    print("=" * 80)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
