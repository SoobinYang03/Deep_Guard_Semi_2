@echo off
chcp 65001 > nul
title DeepGuard Emulator Launcher
echo 안드로이드 분석 환경 구동 시작

set ADB_PATH_INPUT=%1

if "%ADB_PATH_INPUT%"=="" (
    set SDK_PATH=%LOCALAPPDATA%\Android\Sdk
    set ADB_PATH=%SDK_PATH%\platform-tools\adb.exe
) else (
    set ADB_PATH=%ADB_PATH_INPUT%
)

set EMULATOR_PATH=%ADB_PATH:\platform-tools\adb.exe=\emulator\emulator.exe%

if not exist "%EMULATOR_PATH%" (
    echo [오류] 에뮬레이터를 찾을 수 없습니다. 경로 확인: %EMULATOR_PATH%
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

echo [완료] 분석 환경 구축이 완료되었습니다.
exit
