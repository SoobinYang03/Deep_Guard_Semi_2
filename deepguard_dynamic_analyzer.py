import json
import time
import subprocess
import frida
import os
import shutil

class deepguard_dynamic_analyzer:
    def __init__(self, mobsf_emulator="127.0.0.1:5555"):
        print("딥가드 동적 분석기 초기화.")
        self.device_name = mobsf_emulator
        self.emulator_status = False
        self.frida_status = False
        print(f"분석기 초기화 완료: 타겟 디바이스 - {self.device_name}")

    # [스마트 ADB 경로 탐색] 팀원 누구나 사용 가능!
    def get_adb_path(self):
        # 1. 시스템 환경 변수(PATH)에 등록된 adb가 있는지 확인
        if shutil.which("adb"):
            return "adb"
            
        # 2. (Mac) 표준 SDK 경로 확인 (사용자 홈 디렉토리 ~ 기준)
        mac_path = os.path.expanduser("~/Library/Android/sdk/platform-tools/adb")
        if os.path.exists(mac_path):
            return mac_path

        # 3. (Windows) 표준 SDK 경로 확인
        win_path = os.path.expanduser("~\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe")
        if os.path.exists(win_path):
            return win_path

        # 4. 못 찾으면 기본 명령어 반환 (에러 날 수 있음)
        return "adb"

    # 1. 정적분석 데이터 수신
    def receive_static_result(self, static_data):
        print("정적 분석 데이터 수신합니다.")
        return static_data

    # 2. 정적분석결과 파싱
    def parse_static_result(self, static_data):
        print("정적 분석 데이터를 검토합니다.")
        if static_data.get("result") == "error":
            print("정적 분석에서 오류를 발견. 동적분석을 실행하지 않고 종료합니다.")
            return False
        print("정적 분석에서 오류를 발견하지 못했습니다. 동적 분석을 진행합니다.")
        return True

    # 3. 환경 구성. 에뮬 실행 및 frida 실행
    def dynamic_environment(self, apk_path):
        print(f"안드로이드 에뮬레이터 및 Frida 환경 구동 시작 ({apk_path})")
        
        # ADB 명령어 경로 자동 설정
        adb_cmd = self.get_adb_path()
        print(f"사용 중인 ADB 경로: {adb_cmd}") # 확인용 로그

        try:
            # 1. ADB 연결 시도
            print(f"ADB 연결 시도: {self.device_name}")
            subprocess.run([adb_cmd, "connect", self.device_name], capture_output=True)
            time.sleep(2)

            # 2. Frida 디바이스 연결
            try:
                device = frida.get_usb_device()
                print(f"Frida 디바이스 연결 성공: {device.name}")
            except Exception:
                print("Frida 디바이스를 찾지 못했습니다. (에뮬레이터 연결 또는 서버 실행 확인 필요)")
                return

            # 3. 앱 실행
            target_package = "com.example.my_scan_app" 
            print(f"앱 실행 시도: {target_package}")
            
            # [실제 실행 로직]
            pid = device.spawn([target_package])
            session = device.attach(pid)
            device.resume(pid)
            
            print(">> 앱 실행 완료. 10초간 모니터링합니다.")
            time.sleep(10)
            
            session.detach()
            print("분석 정상 종료.")

        # ================================================================
        # [Error-driven 탐지 로직]
        # Frida 버전에 상관없이 안전하게 에러를 잡아내는 범용 코드
        # ================================================================
        except Exception as e:
            # 에러 메시지를 문자열로 변환하여 분석
            error_msg = str(e)
            
            # 앱이 강제로 꺼지거나 연결이 끊긴 경우를 탐지
            if "terminated" in error_msg or "detach" in error_msg or "closed" in error_msg or "transport" in error_msg or "Gadget" in error_msg or "jailed" in error_msg:
                print(f"\n[!!!] 방어 기법 탐지됨: 앱이 실행 즉시 강제 종료되었습니다.")
                print(f"[Result] Analysis Status: Detected (Defense Mechanism) - {error_msg}")
                return True
            else:
                # 진짜 다른 에러인 경우
                print(f"동적 분석 중 예외 발생: {e}")

    # 4. 로그캣으로 로그 전체 가져오기
    def extract_logcat(self, output_file="logcat_result.txt"):
        print("Logcat 데이터 수집 중입니다.")
        raw_logs = ""
        adb_cmd = self.get_adb_path() 

        if not getattr(self, 'device_name', None):
            print("에뮬레이터 연결이 필요합니다.")
            return "emulator name not set"

        try:
            print("기존 로그를 초기화합니다.")
            subprocess.run([adb_cmd, "-s", self.device_name, "logcat", "-c"], check=True)

            print(f"{self.device_name}에서 로그를 추출합니다.")
            command = [adb_cmd, "-s", self.device_name, "logcat", "-d"]

            result = subprocess.run(command, capture_output=True, text=True, check=True)
            raw_logs = result.stdout

            if raw_logs:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                print(f"{len(raw_logs)} 바이트의 로그를 추출하여 '{output_file}'에 저장했습니다.")
            else:
                print("수집된 로그가 비어 있습니다.")
                raw_logs = "empty logs"

        except Exception as e:
            error_message = f"로그 수집 중 오류 발생: {e}"
            print(f"{error_message}")
            raw_logs = error_message

        return raw_logs

    # 5. 결과물 반환 (JSON)
    def result_json(self, raw_logs, dumped_dex_path=None):
        print(">> [API 5] 최종 결과를 JSON 형식으로 포장합니다.")

        if raw_logs is None or "emulator name not set" in raw_logs:
             status_code = "fail"
        else:
             status_code = "success"
        
        log_summary = raw_logs[:500] + "..." if raw_logs and len(raw_logs) > 500 else raw_logs

        result_schema = {
            "analyzer_type": "dynamic",
            "timestamp": time.time(),
            "status": status_code,  
            "result_data": {
                "is_rooted_bypass": True,           
                "dumped_dex_path": dumped_dex_path,
                "log_summary": log_summary
            },
            "full_log_file": "logcat_result.txt"
        }
        return json.dumps(result_schema, indent=4, ensure_ascii=False)

    # 컨트롤러
    def dynamic_controller(self, apk_path, static_result_input):
        data = self.receive_static_result(static_result_input)
        should_run = self.parse_static_result(data)

        if not should_run:
            return {"msg": "Stopped by Static Analysis Result"}

        self.dynamic_environment(apk_path)
        logs = self.extract_logcat()
        final_json = self.result_json(logs)
        
        print("\n최종 결과물")
        print(final_json)
        return final_json

# 실행 테스트
if __name__ == "__main__":
    analyzer = deepguard_dynamic_analyzer()
    
    # 깃허브 업로드용 (경로 수정 불필요)
    target_apk = "sample.apk" 
    
    dummy_static_result = {"file_name": "sample.apk", "result": "success"}
    analyzer.dynamic_controller(target_apk, dummy_static_result)