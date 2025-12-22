import json
import time
import subprocess


class deepguard_dynamic_analyzer:
    def __init__(self):
        # 에뮬레이터의 설정을 입력하는 부분.
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
    def extract_logcat(self):
        print("Logcat 데이터 수집를 수집중입니다.")

        raw_logs = "System Log: Application Started... "

        return raw_logs

    #5. 결과물 반환.
    def result_json(self, raw_logs):
        print("최종 결과를 JSON파일로 반환합니다.")

        result_schema = {
            "analyzer": "dynamic_analyze",
            "timestamp": time.time(),
            "logs": raw_logs,
            "status": "complete"
        }

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
        print("\n--- 최종 결과물 ---")
        print(final_json)
        return final_json


#데모파일 테스트
if __name__ == "__main__":
    analyzer = deepguard_dynamic_analyzer()

    dummy_static_result = {"file_name": "test.apk", "result": "success"}
    analyzer.dynamic_controller("C:/apk/test.apk", dummy_static_result)