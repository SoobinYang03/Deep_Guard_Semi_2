import json
import time
import subprocess


class deepguard_dynamic_analyzer:
    def __init__(self):
        # 에뮬레이터의 설정을 입력하는 부분.
        #self.device_name = device_name - 에뮬레이터 이름 결정 후 입력.
        self.emulator_status = False

    #1. 정적분석 데이터 수신(동균님과 협업이 필요)
    def receive_static_result(self, static_data):
        print("정적 분석 데이터 수신합니다.")
        return static_data

    #2. 정적분석결과 파싱
    def parse_static_result(self, static_data):
        print("정적 분석 데이터를 검토합니다.")

        if static_data.get("result") == "error":
            print("정적 분석에서 오류를 발견. 동적분석을 실행하지 않고 종료합니다.")
            return False

        print("정적 분석에서 오류를 발견하지 못했습니다. 동적 분석을 진행합니다.")
        return True

    #3. 환경 구성. 에뮬 실행 및 frida 실행
    def dynamic_environment(self, apk_path):
        print(f"안드로이드 에뮬레이터 및 Frida 환경 구동 시작 ({apk_path})")


        time.sleep(2)
        print(">> 환경 구동 및 앱 실행 완료")

    #4. 로그캣으로 로그 전체 가져오기.
    def extract_logcat(self, output_file="logcat_result.txt"):
        print("Logcat 데이터 수집를 수집중입니다.")

        raw_logs = ""

        if not getattr(self, 'device_name', None):
            print("에뮬레이터 연결이 필요합니다.")
            return "emulator name not set"

        try:
            print("기존 로그를 초기화합니다.")
            subprocess.run(["adb", "-s", self.device_name, "logcat", "-c"], check=True)

            print(f"{self.device_name}에서 로그를 추출합니다.")
            command = ["adb", "-s", self.device_name, "logcat", "-d"]

            result = subprocess.run(command, capture_output=True, text=True, check=True)
            raw_logs = result.stdout

            if raw_logs:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                print(f"{len(raw_logs)} 바이트의 로그를 추출하여 '{output_file}'에 저장했습니다.")

            else:
                print("수집된 로그가 비어 있습니다.")
                raw_logs = "empty logs"

        except subprocess.CalledProcessError as e:
            error_message = f"ADB 명령 실행 중 오류 발생. {e}"
            print(f"{error_message}")
            raw_logs = error_message

        except FileNotFoundError:
            error_message = "adb 명령 자체를 찾을 수 없습니다. 환경 변수 설정을 확인해주세요."
            print(f"{error_message}")
            raw_logs = error_message

        except Exception as e:
            error_message = f"예상치 못한 오류 발생 {e}"
            print(f"{error_message}")
            raw_logs = error_message

        return raw_logs

    # 5. 결과물 반환 ( 통합 스키마 적용 및 DEX 덤프 경로 추가)
    def result_json(self, raw_logs, dumped_dex_path=None):
        print(">> [API 5] 최종 결과를 JSON 형식으로 포장합니다.")

        # 1. 분석 상태 판단 (덤프된 DEX 파일이 존재하면 '성공'으로 간주)
        status_code = "success" if dumped_dex_path else "fail"
        
        # 2. 로그 요약 (너무 길면 DB에 안 들어가므로 앞부분만 자름)
        log_summary = raw_logs[:500] + "..." if raw_logs and len(raw_logs) > 500 else raw_logs

        # 3. 딥가드 통합 스키마 (DeepGuard Schema) 맞춤
        result_schema = {
            "analyzer_type": "dynamic",         # 분석기 종류: 동적 분석
            "timestamp": time.time(),           # 분석 완료 시간
            "status": status_code,              # 분석 성공 여부 (success/fail)
            
            # [핵심 데이터 영역]
            "result_data": {
                "is_rooted_bypass": True,           # 프리다 우회 시도 여부
                "dumped_dex_path": dumped_dex_path, # 추출된 악성코드 파일 경로 (지금은 None)
                "log_summary": log_summary          # 로그 요약
            },
            
            # 전체 로그 파일이 저장된 경로
            "full_log_file": "logcat_result.txt"
        }

        # 4. JSON 변환
        return json.dumps(result_schema, indent=4, ensure_ascii=False)

    #컨트롤러
    def dynamic_controller(self, apk_path, static_result_input):

        #1 함수 실행
        data = self.receive_static_result(static_result_input)

        #2 함수 실행
        should_run = self.parse_static_result(data)

        if not should_run:
            return {"msg": "Stopped by Static Analysis Result"}

        #3 함수 실행
        self.dynamic_environment(apk_path)

        #4 함수 실행
        logs = self.extract_logcat()

        #5 함수 실행
        final_json = self.result_json(logs)
        print("\n최종 결과물")
        print(final_json)
        return final_json


#데모파일 테스트
if __name__ == "__main__":
    analyzer = deepguard_dynamic_analyzer()

    dummy_static_result = {"file_name": "test.apk", "result": "success"}
    analyzer.dynamic_controller("C:/apk/test.apk", dummy_static_result)
