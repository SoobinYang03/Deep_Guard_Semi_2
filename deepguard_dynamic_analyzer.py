import json
import time
import subprocess
import os
import frida
import re
import shutil
from threat_signature import malicious_behavior

class deepguard_dynamic_analyzer:
    def __init__(self, mobsf_emulator="127.0.0.1:5555"):

        print("딥가드 동적 분석기 초기화.")

        self.device_name = mobsf_emulator
        self.output_dir = "dumped_dex"
        self.current_session = None
        self.adb_path = self.get_adb_path()

        print(f"분석기 초기화 완료: 타겟 디바이스 -{self.device_name}")

    #API1. OS에 구애받지 않는 ADB경로 탐색
    def get_adb_path(self):
        #1-1. 시스템 환경 변수(PATH)에 등록된 adb가 있는지 확인
        if shutil.which("adb"):
            return "adb"

        #1-2. 표준 SDK 경로 확인 (사용자 홈 디렉토리 ~ 기준)
        mac_path = os.path.expanduser("~/Library/Android/sdk/platform-tools/adb")
        if os.path.exists(mac_path):
            return mac_path

        #1-3. (Windows) 표준 SDK 경로 확인
        win_path = os.path.expanduser("~\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe")
        if os.path.exists(win_path):
            return win_path

        #1-4. 못 찾으면 기본 명령어 반환 (에러 날 수 있음)
        return "adb"

    #API2. 정적분석 데이터 수신
    def receive_static_result(self, run_id):
        base_path = os.path.join(os.getcwd(), "out_runs_b", run_id)
        evidence_path = os.path.join(base_path, "evidence.json")
        interpretation_path = os.path.join(base_path, "interpretation.json")

        print(f"API2: 정적 분석 결과 수신 시작. 경로: {base_path})")

        try:
            with open(evidence_path, 'r', encoding='utf-8') as f:
                evidence_data = json.load(f)
            with open(interpretation_path, 'r', encoding='utf-8') as f:
                interpretation_data = json.load(f)

            print(f"'{run_id}' 폴더에서 데이터를 성공적으로 수신.")
            return evidence_data, interpretation_data
        except Exception as e:
            print(f"API2 오류: '{run_id}' 폴더를 찾을 수 없거나 파일이 손상됨. ({e})")
            return None, None

    #API3. 정적분석결과 파싱. 모드 설정에 따른 로직 설정.
    def parse_static_result(self, evidence, interpretation, mode):
        print(f"정적 분석 데이터를 검토합니다.(모드:{mode})")

        if not evidence or not interpretation:
            print("파싱 실패: 입력 데이터가 비어 있습니다.")
            return {"action": "stop", "reason": "empty data"}

        pkg_name = evidence.get("evidence", {}).get("apk.info", {}).get("package_name")

        if not pkg_name:
            apk_path = evidence.get("inputs", {}).get("apk_path", "")
            pkg_name = self.get_package_name(apk_path) if apk_path else "unknown"

        static_tags = interpretation.get("tags", [])
        mitre_techniques = interpretation.get("mitre", {}).get("techniques", [])

        is_dangerous = len(static_tags) > 0

        result_plan = {
            "package_name": pkg_name,
            "static_tags": static_tags,
            "mitre_info": mitre_techniques,
            "action": "run",
            "hints": static_tags,
            "reason": ""
        }

        if mode == "speedy":
            if is_dangerous:
                print(f"Speedy Mode. 유도형 동적 분석을 실행합니다. {static_tags}")
                return {"action": "run", "hints": static_tags, "package_name": pkg_name}
            return {"action": "stop", "reason": "fast mode + static safe"}

        elif mode == "exact":
            print(f"Exact Mode. 제로트러스트 원칙 적용. 전수조사를 실행합니다.")
            return {"action": "run", "hints": [], "package_name": pkg_name}

        return {"action": "stop", "reason": "unknown mode"}


    #API4. apk파일의 패키지 이름 추출
    def get_package_name(self, apk_path):
        if not apk_path or not os.path.exists(apk_path): return None
        try:
            result = subprocess.run(["aapt", "dump", "badging", apk_path], capture_output=True, text=True,
                                    encoding='utf-8')
            match = re.search(r"package: name='([^']+)'", result.stdout)
            return match.group(1) if match else None

        except Exception as e:
            print(f"패키지 이름 추출 실패: {e}")
            return None

    #API5. 환경 구성. 에뮬 실행 및 frida 실행(민성님의 agent.js 연동)
    def dynamic_environment(self, apk_path, hints=None):

        print(f"안드로이드 에뮬레이터 및 Frida 환경 구동 시작 ({apk_path})")
        try:
            #5-1 에뮬레이터 실행
            print("에뮬레이터 구동 스크립트(deepguard_emulator.bat)를 실행합니다...")
            subprocess.run(["deepguard_emulator.bat", self.adb_path], shell=True)

            #5-2 에뮬레이터 연결 여부 확인
            print("에뮬레이터 응답 대기 중...")
            connected = False
            for i in range(15):
                subprocess.run([self.adb_path, "connect", self.device_name], capture_output=True)

                check = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True)
                if self.device_name in check.stdout and "device" in check.stdout and "offline" not in check.stdout:
                    print(f"에뮬레이터 연결 확인 {i + 1}회 시도함.")
                    connected = True
                    break
                time.sleep(2)
            if not connected:
                print("에뮬레이터 연결 시간이 초과.")
                return False

            #5-3 안드로이드 패키지 매니저 준비
            print("안드로이드 패키지 매니저 대기 중.")
            for i in range(20):
                boot_check = subprocess.run([self.adb_path, "-s", self.device_name, "shell", "getprop", "sys.boot_completed"],
                                            capture_output=True, text=True)
                if "1" in boot_check.stdout:
                    print(f"시스템 부팅 완료 확인! ({i + 1}회 시도)")
                    break
                time.sleep(2)

            #5-4 루트 권한 확인 및 재부여
            subprocess.run([self.adb_path, "connect", self.device_name], capture_output=True)
            subprocess.run([self.adb_path, "-s", self.device_name, "root"], capture_output=True)
            time.sleep(2)

            #5-5 Frida서버 실행
            print(f"분석 에뮬레이터 구동{self.device_name}")
            subprocess.run([self.adb_path, "connect", self.device_name], capture_output=True)
            subprocess.run([self.adb_path, "-s", self.device_name, "forward", "tcp:27042", "tcp:27042"], capture_output=True)
            subprocess.Popen([self.adb_path, "-s", self.device_name, "shell", "/data/local/tmp/re_frida_server &"], shell=True)
            time.sleep(3)

            print("패키지 매니저 서비스 응답 대기 중.")
            for i in range(15):
                pm_check = subprocess.run([self.adb_path, "-s", self.device_name, "shell", "pm", "path", "android"],
                                          capture_output=True, text=True)
                if "package:" in pm_check.stdout:
                    print(f"패키지 매니저 서비스 가동 확인 ({i + 1}회 시도)")
                    break
                print(f"패키지 매니저 대기 중... ({i + 1}/15)")
                time.sleep(3)

            #5-6 APK파일 설치
            print(f"분석용 APK 설치 중: {apk_path}")
            install_result = subprocess.run(
                [self.adb_path, "-s", self.device_name, "install", "-r", apk_path], capture_output=True, text=True, encoding='utf-8'
            )

            if "Success" not in install_result.stdout:
                print(f"설치 실패: {install_result.stderr}")
                return "error", []


            #5-7 패키지 추출 및 apk 실행
            package_name = self.get_package_name(apk_path)
            if not package_name:
                print("패키지명을 추출할 수 없습니다.")
                return "error", []

            #5-8 안드로이드 패키지 매니저가 패키지명 확인
            check_pkg = subprocess.run([self.adb_path, "-s", self.device_name, "shell", "pm", "list", "packages", package_name],
                                       capture_output=True, text=True)
            if package_name not in check_pkg.stdout:
                print(f"기기 내에 {package_name} 패키지가 존재하지 않습니다.")
                return "error", []

            device = frida.get_usb_device(timeout=10)
            print(f"Frida서버 내에서 실행하는 중...")
            pid = device.spawn([package_name])
            self.current_session = device.attach(pid)

            #5-9 agent.js 로드 및 메시지 핸들러 등록
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
                print(f"speedy 모드. 유도형 힌트 적용 분석 중...")
            else:
                print(f"exact 모드. 전체 전수 조사 분석 중...")

            time.sleep(20)  # 분석 지속 시간

            #5-10 정상 분석 이후, 끝났으니 에뮬레이터 종료
            self.current_session.detach()
            print("Frida 세션이 성공적으로 해제되었습니다.")
            return "success", []

        #5-11 방어기법을 탐지했을 경우.
        except Exception as e:
            error_msg = str(e).lower()
            critical_keywords = ["terminated", "detach", "closed", "transport", "gadget", "jailed"]

            if any(key in error_msg for key in critical_keywords):
                print(f"\n방어 기법 탐지됨: {error_msg}")
                print("탐지 방어기법에 의해 세션이 종료되었습니다. 위험 파일로 판단합니다.")

                detection_tag = {
                    "id": "dg.dynamic.anti_analysis_detected",
                    "severity": "high",
                    "reason": f"Analysis blocked by app (Anti-Analysis): {error_msg}",
                    "mitre": ["T1622"]
                }
                return "detected", [detection_tag]

            print(f"기타 실행 에러 발생: {e}")
            return "error", []

        #5-12 방어기법으로 검사가 정상적으로 끝나지 않아도 에뮬레이터는 끈다.
        finally:
            print("분석 환경 정리 중: 에뮬레이터 종료.")
            subprocess.run([self.adb_path, "emu", "kill"], shell=False)

    #API6. 로그캣으로 로그 전체 가져오기.
    def extract_logcat(self, output_file="logcat_result.txt"):
        print("Logcat 데이터 수집를 수집중입니다.")

        if not getattr(self, 'device_name', None):
            print("에뮬레이터 연결이 필요합니다.")
            return "emulator name not set"

        try:
            print(f"{self.device_name}에서 로그를 추출합니다.")
            command = [self.adb_path, "-s", self.device_name, "logcat", "-d"]

            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='ignore', check=True)
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

    #API7. 표준정규식으로 인한 탐지 로직 고도화
    def regex_filtering(self, raw_logs, static_data, mode):
        filtered_results = []

        target_behavior = static_data.get("static_to_dynamic",{}).get("behavior",[])

        for category, info in malicious_behavior.items():

            if mode == "speedy" and category not in target_behavior:
                continue

            if re.search(info["pattern"], raw_logs, re.IGNORECASE):
                filtered_results.append({
                    "category": category,
                    "description": info["desc"],
                    "risk_level": "Critical"
                })

        return filtered_results

    #API8. 결과물 반환.
    def result_json(self, filtered_results, mode, dumped_dex_path=None):
        print(f"최종 결과를 JSON파일로 반환합니다.({mode})")

        status = "success" if isinstance(filtered_results, list) else "fail"

        result_schema = {
            "analyzer": "dynamic_analyze",
            "analysis_mode" : mode,
            "timestamp": time.time(),
            "status": status,
            "result_data" : {
                "dumped_dex_path" : dumped_dex_path,
                "detected_count": len(filtered_results) if isinstance(filtered_results, list) else 0,
                "log_summary" : filtered_results[:100] if (status == "success" and len(filtered_results) > 0) else "no logs"
            },
            "full_log_file" : "deepguard_second_result.txt"
        }

        return json.dumps(result_schema, indent=4, ensure_ascii=False)

    #컨트롤러
    def dynamic_controller(self, apk_path, run_id, mode="speedy", raw_logs=None):

        #API1 실행
        evidence, interpretation = self.receive_static_result(run_id)
        if not evidence:
            return {"error": "Static data not found"}

        #API2 실행
        plan = self.parse_static_result(evidence, interpretation, mode)

        if plan["action"] == "stop":
            print(f"분석 중단. {plan.get('reason')}")
            return {"msg": f"정적 분석결과에 의해 중단. {plan.get('reason')}"}

        #API3 함수 실행
        status, detected_tags = self.dynamic_environment(apk_path, hints=plan.get("hints"))

        #API4 실행
        reallogs = self.extract_logcat()
        filtered_logs = self.regex_filtering(reallogs, interpretation, mode)

        #API5 실행
        dump_path = self.output_dir if os.path.exists(self.output_dir) and os.listdir(self.output_dir) else None
        final_json = self.result_json(filtered_logs, mode, dump_path)

        print("\n최종 결과물")
        print(final_json)
        return final_json


#데모파일 테스트
if __name__ == "__main__":
    analyzer = deepguard_dynamic_analyzer(mobsf_emulator="127.0.0.1:5555")

    test_run_id = "test_analysis_report_001"
    apk_file_name = "sample.apk"

    base_path = os.path.join(os.getcwd(), "out_runs_b", test_run_id)
    os.makedirs(base_path, exist_ok=True)

    mock_evidence = {
        "evidence": {
            "apk.info": {
                "package_name": "com.example.malware.sample"
            }
        },
        "inputs": {
            "apk_path": apk_file_name
        }
    }

    mock_interpretation = {
        "tags": ["T_SMS_SEND", "T_NET_CONNECT"],
        "mitre": {
            "techniques": ["T1071", "T1132"]
        },
        "static_to_dynamic": {
            "behavior": ["sms", "record", "account_theft"]
        }
    }

    with open(os.path.join(base_path, "evidence.json"), "w", encoding="utf-8") as f:
        json.dump(mock_evidence, f, indent=4)
    with open(os.path.join(base_path, "interpretation.json"), "w", encoding="utf-8") as f:
        json.dump(mock_interpretation, f, indent=4)

    print(f"\n--- 테스트 환경 구성 완료: {test_run_id} ---")

    try:
        final_report = analyzer.dynamic_controller(
            apk_path=apk_file_name,
            run_id=test_run_id,
            mode="speedy"
        )

        print("\n" + "=" * 50)
        print("최종 동적 분석 리포트 결과")
        print("=" * 50)
        print(final_report)

    except Exception as e:
        print(f"\n[실행 중단] 동적 분석 중 오류 발생: {e}")
