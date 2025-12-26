import json
import time
import subprocess
import os

class deepguard_dynamic_analyzer:
       def __init__(self, mobsf_emulator="127.0.0.1:5555"):

        print("딥가드 동적 분석기 초기화.")

        self.device_name = mobsf_emulator
        self.emulator_status = False
        self.frida_status = False

        print(f"분석기 초기화 완료: 타겟 디바이스 -{self.device_name}")

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

    #3-a apk파일의 패키지 이름 추출
    def get_package_name(self, apk_path):
        try:
            result = subprocess.run(["aapt", "dump", "badging", apk_path], capture_output=True, text=True, encoding='utf-8')

            for line in result.stdout.splitlines():

                if line.startswith("package: name="):
                    return line.split("'")[1]

        except Exception as e:
            print(f"패키지 이름 추출 실패: {e}")
            return None

    #3. 환경 구성. 에뮬 실행 및 frida 실행
    def dynamic_environment(self, apk_path):
        print(f"안드로이드 에뮬레이터 및 Frida 환경 구동 시작 ({apk_path})")

        try:
            print(f"분석 에뮬레이터 구동{self.device_name}")
            subprocess.run(["adb", "connect", self.device_name], capture_output = True)
            self.emulator_status = True

            check_frida = subprocess.run(["adb", "-s", self.device_name, "shell", "ps | grep frida"], capture_output=True, text=True)

            if "frida" in check_frida.stdout:
                print("Frida 서버를 실행합니다.")
            subprocess.Popen(["adb", "-s", self.device_name, "shell", "su -c /data/local/tmp/re_frida_server &"], shell = True, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)

            time.sleep(2)

            self.frida_status = True
            print("Frida 서버 준비 완료.")

            #
            #
            #
            #
            #

            if not os.path.exists(apk_path):
                print(f"APK 파일을 찾을 수 없습니다. : {apk_path}")
                return False

            print(f"APK 설치 시작: {os.path.basename(apk_path)}")
            subprocess.run(["adb", "-s", self.device_name, "install", "-r", apk_path], check=True)
            print("APK 설치 완료.")


            package_name = self.get_package_name(apk_path)
            if package_name:
                print(f"앱 실행 중: {package_name}")
                subprocess.run(["adb", "-s", self.device_name, "shell", "monkey", "-p", package_name, "-c",
                            "android.intent.category.LAUNCHER", "1"],
                           capture_output=True)
                print(f"환경 구동 및 앱 실행 완료.")
            else:
                print("패키지명을 찾을 수 없습니다.")

            return True

        except subprocess.CalledProcessError as e:
            print(f"ADB 명령 실패: {e}")
            return False
        except Exception as e:
            print(f"예상치 못한 오류 발생: {e}")
            return False

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

   # 5. 결과물 반환 (철호님 피드백 반영: 덤프 없어도 로그 있으면 성공)
    def result_json(self, raw_logs, dumped_dex_path=None):
        print(">> [API 5] 최종 결과를 JSON 형식으로 포장합니다.")

        # [수정된 핵심 로직]
        # 1. 덤프 파일 유무가 아니라, 로그 수집 과정에서 '치명적인 에러'가 있었는지를 봅니다.
        # 2. 로그가 비어있거나, 에뮬레이터 연결 에러가 명시된 경우만 'fail'
        if raw_logs is None or "emulator name not set" in raw_logs or "adb 명령 자체를 찾을 수 없습니다" in raw_logs:
             status_code = "fail"
        else:
             # 덤프 파일(dumped_dex_path)이 None이어도, 로그가 정상 수집되었다면 분석은 '성공'입니다.
             status_code = "success"
        
        # 로그 요약 (DB 저장용으로 너무 길지 않게 자름)
        log_summary = raw_logs[:500] + "..." if raw_logs and len(raw_logs) > 500 else raw_logs

        # 딥가드 통합 스키마
        result_schema = {
            "analyzer_type": "dynamic",
            "timestamp": time.time(),
            "status": status_code,  
            
            "result_data": {
                "is_rooted_bypass": True,           
                "dumped_dex_path": dumped_dex_path, # 없으면 null로 나가지만 status는 success가 될 수 있음
                "log_summary": log_summary
            },
            
            "full_log_file": "logcat_result.txt"
        }

        return json.dumps(result_schema, indent=4, ensure_ascii=False)

    #컨트롤러
    def dynamic_controller(self, apk_path, static_result_input):

        #api1. 정적분석 수신 실행
        data = self.receive_static_result(static_result_input)

        #api2. 수신결과 파싱 실행
        should_run = self.parse_static_result(data)

        if not should_run:
            return {"msg": "정적분석 결과가 충분하여 동적분석의 동작을 중지합니다."}

        #api3. MobSF에서 에뮬레이터 구동 및 Frida. APK파일 실행
        self.dynamic_environment(apk_path)

        #api4. log추출 실행.
        logs = self.extract_logcat()

        #api5. 결과물을 deepguard의 통합 schema에 맞게 정리 실행.
        final_json = self.result_json(logs)
        print("\n최종 결과물")
        print(final_json)
        return final_json


#데모파일 테스트
if __name__ == "__main__":
    analyzer = deepguard_dynamic_analyzer()

    dummy_static_result = {"file_name": "test.apk", "result": "success"}
    analyzer.dynamic_controller("C:/apk/test.apk", dummy_static_result)



