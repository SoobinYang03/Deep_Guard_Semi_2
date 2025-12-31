@echo off
chcp 65001 > nul
title DeepGuard Emulator Launcher (Distribution Ver.)
echo ==========================================
echo 안드로이드 분석 환경 구동 시작
echo ==========================================

set SDK_PATH=%LOCALAPPDATA%\Android\Sdk
set EMULATOR_PATH=%SDK_PATH%\emulator\emulator.exe
set ADB_PATH=%SDK_PATH%\platform-tools\adb.exe

if not exist "%EMULATOR_PATH%" (
    echo 안드로이드 SDK를 찾을 수 없습니다.
    echo 기본 경로 확인: %SDK_PATH%
    pause
    exit
)

echo 에뮬레이터(Pixel_5)를 구동 중입니다...

start "" "%EMULATOR_PATH%" -avd Pixel_5 -writable-system -no-snapshot

echo 시스템 초기 응답 대기 중 (약 15초)...
ping 127.0.0.1 -n 16 > nul

echo ADB 연결 시도 (127.0.0.1:5555)...
"%ADB_PATH%" connect 127.0.0.1:5555

echo 루트 권한(adb root) 활성화...
"%ADB_PATH%" -s 127.0.0.1:5555 root

echo ==========================================
echo [완료] 분석 환경 구축이 완료되었습니다.
echo 이제 deepguard_dynamic_analyzer.py를 실행하세요!
echo ==========================================
timeout /t 5
exit