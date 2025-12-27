import json
import time
import subprocess
import os
import frida

class deepguard_dynamic_analyzer:
    def __init__(self, mobsf_emulator="127.0.0.1:5555"):

        print("딥가드 동적 분석기 초기화.")

        self.device_name = mobsf_emulator
        self.output_dir = "dumped_dex"
        self.emulator_status = False
        self.frida_status = False
        self.current_session = None

        print(f"분석기 초기화 완료: 타겟 디바이스 -{self.device_name}")

    #1. 정적분석 데이터 수신
    def receive_static_result(self, static_data):
        print("정적 분석 데이터를 수신합니다.")
        return static_data

    #2. 정적분석결과 파싱. 모드 설정에 따른 로직 설정.
    def parse_static_result(self, static_data, mode):
        print(f"정적 분석 데이터를 검토합니다.(모드:{mode})")
        severity = static_data.get("leaks", {}).get("severity", "safe")
        tags = static_data.get("leaks", {}).get("tags", [])
        is_dangerous = (severity != "safe")

        if mode == "fast":
            if is_dangerous:
                print(f"정적 분석간 위협을 발견했습니다. 유도형 분석을 실행합니다. ({tags})")
                return {"action": "run", "hints": tags}
            return {"action": "stop", "reason": "fast mode + static safe"}

        elif mode == "detailed":
            print("상세분석 모드. 제로 트러스트의 원칙 적용. 전수조사를 시작합니다.")
            return {"action": "run", "hints": []}

        return {"action": "stop", "reason": "unknown mode"}


    #3-1 apk파일의 패키지 이름 추출
    def get_package_name(self, apk_path):
        try:
            result = subprocess.run(["aapt", "dump", "badging", apk_path], capture_output=True, text=True, encoding='utf-8')

            for line in result.stdout.splitlines():

                if line.startswith("package: name="):
                    return line.split("'")[1]

        except Exception as e:
            print(f"패키지 이름 추출 실패: {e}")
            return None

    #3. 환경 구성. 에뮬 실행 및 frida 실행(민성님의 agent.js 연동)
    def dynamic_environment(self, apk_path, hints=None):
        print(f"안드로이드 에뮬레이터 및 Frida 환경 구동 시작 ({apk_path})")

        try:
            #3-a. 에뮬레이터 연결 및 Frida 서버 실행
            print(f"분석 에뮬레이터 구동{self.device_name}")
            subprocess.run(["adb", "connect", self.device_name], capture_output=True)
            subprocess.Popen(["adb", "-s", self.device_name, "shell", "su -c /data/local/tmp/re_frida_server &"], shell=True)
            time.sleep(2)

            #3-b. 패키지 추출 및 apk 실행
            package_name = self.get_package_name(apk_path)
            device = frida.get_usb_device()
            pid = device.spawn([package_name])
            self.current_session = device.attach(pid)

            #3-c. agent.js 로드 및 메시지 핸들러 등록
            with open("agent.js", "r", encoding="utf-8") as f:
                script_code = f.read()

            script = self.current_session.create_script(script_code)

            def on_message(message, data):
                if message['type'] == 'send' and message['payload'].get("type") == "dex_dump":
                    if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)
                    file_name = f"{self.output_dir}/dump_{message['payload']['addr']}.dex"
                    with open(file_name, "wb") as f:
                        f.write(data)
                    print(f"dex dump 저장 완료: {file_name}")

            script.on('message', on_message)
            script.load()
            device.resume(pid)

            if hints:
                print(f"Fast 모드. 유도형 힌트 적용 분석 중...")
            else:
                print(f"Detailed 모드. 전체 전수 조사 분석 중...")

            time.sleep(20)  # 분석 지속 시간

            #3-d. 분석이 끝났으니 에뮬레이터 종료
            self.current_session.detach()
            print("Frida 세션이 성공적으로 해제되었습니다.")
            return True

        except Exception as e:
            print(f"예기치 못한 오류 발생: {e}")
            return False

    #4. 로그캣으로 로그 전체 가져오기.
    def extract_logcat(self, output_file="logcat_result.txt"):
        print("Logcat 데이터 수집를 수집중입니다.")

        if not getattr(self, 'device_name', None):
            print("에뮬레이터 연결이 필요합니다.")
            return "emulator name not set"

        try:
            subprocess.run(["adb", "-s", self.device_name, "logcat", "-c"], check=True)

            print(f"{self.device_name}에서 로그를 추출합니다.")
            command = ["adb", "-s", self.device_name, "logcat", "-d"]

            result = subprocess.run(command, capture_output=True, text=True, check=True)
            raw_logs = result.stdout

            if raw_logs:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(raw_logs)
                return raw_logs

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

    #5. 결과물 반환.
    def result_json(self, raw_logs, mode, dumped_dex_path=None):
        print(f"최종 결과를 JSON파일로 반환합니다.({mode})")

        status = "success"
        if raw_logs is None or "emulator" in raw_logs:
            status = "fail"

        result_schema = {
            "analyzer": "dynamic_analyze",
            "analysis_mode" : mode,
            "timestamp": time.time(),
            "logs": raw_logs,
            "status": status,
            "result_data" : {
                "dumped_dex_path" : dumped_dex_path,
                "log_summary" : raw_logs[:500] + "..." if raw_logs else "no logs"
            },
            "full_log_file" : "logcat_result.txt"
        }

        return json.dumps(result_schema, indent=4, ensure_ascii=False)

    #컨트롤러
    def dynamic_controller(self, apk_path, static_result_input, mode="fast"):

        #API1 실행
        data = self.receive_static_result(static_result_input)

        #API2 실행
        plan = self.parse_static_result(data, mode)

        if plan["action"] == "stop":
            print(f"분석 중단. {plan.get('reason')}")
            return {"msg": f"정적 분석결과에 의해 중단. {plan.get('reason')}"}

        #API3 함수 실행
        success = self.dynamic_environment(apk_path, hints=plan.get("hints"))

        if not success:
            return {"msg": "환경구성에 실패했습니다."}

        #API4 실행
        logs = self.extract_logcat()

        #API5 실행
        dump_path = self.output_dir if os.path.exists(self.output_dir) and os.listdir(self.output_dir) else None
        final_json = self.result_json(logs, mode, dump_path)

        print("\n최종 결과물")
        print(final_json)
        return final_json


#데모파일 테스트
if __name__ == "__main__":
    analyzer = deepguard_dynamic_analyzer()

    dummy_static_result = {
        "leaks": {
            "severity": "critical",
            "tags": ["T_SMS_SEND", "T_NET_CONNECT"]
        }
    }

    analyzer.dynamic_controller("test.apk", dummy_static_result, mode="fast")
