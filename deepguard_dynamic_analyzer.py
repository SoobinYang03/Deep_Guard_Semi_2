import json
import time
import subprocess
import os
import frida
import re
import shutil
import requests
from dotenv import load_dotenv
from threat_signature import malicious_behavior

# .env 파일 로드
load_dotenv()

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

    #API5. MobSF 동적 분석 수행
    def dynamic_environment(self, file_hash, package_name, run_id, hints=None):

        print(f"MobSF 동적 분석 시작 (Hash: {file_hash})")
        
        try:
            # MobSF 설정 (.env 파일에서 로드)
            mobsf_url = os.getenv("MOBSF_URL", "http://127.0.0.1:8000")
            api_key = os.getenv("MOBSF", "")
            
            if not api_key:
                print("✗ MOBSF API 키가 .env 파일에 없습니다.")
                print("   .env 파일에 MOBSF=<API_KEY>를 설정하세요.")
                return "error", []
            
            # MobSF API 헤더
            headers = {
                "AUTHORIZATION": api_key
            }
            
            print(f"MobSF URL: {mobsf_url}")
            print(f"API Key: {api_key[:20]}...")
            print(f"Package: {package_name}")
            
            # 1. 동적 분석 시작
            print(f"\n1. 동적 분석 시작 요청...")
            
            dynamic_start_url = f"{mobsf_url}/api/v1/dynamic/start_analysis"
            dynamic_data = {
                "hash": file_hash
            }
            
            print(f"   Hash: {file_hash}")
            print(f"   MobSF 동적 분석 시작 중...")
            
            # 동적 분석 실행
            response = requests.post(
                dynamic_start_url,
                headers=headers,
                data=dynamic_data,
                timeout=30
            )
            
            if response.status_code == 200:
                print(f"✓ 동적 분석 시작됨")
                result = response.json()
                print(f"   결과: {result}")
                
                # MobSF에서 반환한 액티비티 정보 추출
                mobsf_activities = result.get('activities', [])
                mobsf_exported_activities = result.get('exported_activities', [])
                mobsf_deeplinks = result.get('deeplinks', {})
            else:
                print(f"✗ 동적 분석 시작 실패: {response.status_code}")
                print(f"   응답: {response.text}")
                return "error", []
            
            # 1-1. Frida 서버 시작
            print(f"\n1-1. Frida 서버 시작 중...")
            
            try:
                cmd = f'{self.adb_path} -s {self.device_name} shell /system/fd_server'
                subprocess.run(cmd, shell=True, timeout=5)
                print(f"   ✓ Frida 서버 시작 완료")
                time.sleep(2)
            except Exception as e:
                print(f"   ⚠ Frida 서버 시작 실패: {str(e)[:50]}")
            
            # 1-2. Frida spawn 모드로 앱 시작
            print(f"\n1-2. Frida agent.js로 DEX 덤프...")
            agent_path = os.path.join("dynamic_analysis", "agent.js")
            
            if os.path.exists(agent_path):
                try:
                    import frida
                    
                    # Frida Python API 사용 - agent.js로 DEX 덤프
                    print(f"   Frida로 {package_name} spawn 중 (DEX 덤프)...")
                    device = frida.get_usb_device()
                    pid = device.spawn([package_name])
                    session = device.attach(pid)
                    
                    # agent.js 로드 (DEX 덤프)
                    with open(agent_path, 'r', encoding='utf-8') as f:
                        script_code = f.read()
                    
                    script = session.create_script(script_code)
                    
                    # DEX 덤프 메시지 핸들러
                    dex_count = [0]  # 카운터를 리스트로 (nonlocal 대신)
                    
                    def on_message(message, data):
                        if message['type'] == 'send':
                            payload = message.get('payload', {})
                            
                            if payload.get('type') == 'dex_dump':
                                dex_count[0] += 1
                                addr = payload.get('addr', 'unknown')
                                size = payload.get('size', 0)
                                
                                # DEX 파일 저장
                                dex_filename = f"dumped_dex_{dex_count[0]}_{addr.replace('0x', '')}.dex"
                                dex_path = os.path.join("out_runs_b", run_id, dex_filename)
                                
                                with open(dex_path, 'wb') as f:
                                    f.write(data)
                                
                                print(f"   [DEX #{dex_count[0]}] 저장됨: {dex_filename} ({size} bytes)")
                            else:
                                # 일반 로그 출력
                                print(f"   [Frida] {payload}")
                        elif message['type'] == 'error':
                            print(f"   [Error] {message.get('description', '')}")
                    
                    script.on('message', on_message)
                    script.load()
                    device.resume(pid)
                    
                    print(f"   ✓ agent.js 실행 중 (PID: {pid})")
                    print(f"   30초 대기 (DEX 덤프 완료까지)...")
                    time.sleep(30)  # DEX 덤프 완료 대기
                    
                    # agent.js 세션 종료
                    print(f"   agent.js 종료 중...")
                    device.kill(pid)
                    session.detach()
                    print(f"   ✓ agent.js 종료 완료")
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"   ⚠ agent.js 실행 실패: {str(e)[:100]}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"   ⚠ agent.js 파일을 찾을 수 없습니다: {agent_path}")
            
            # 1-3. bypass.js로 새로 spawn (Activity.finish() 차단)
            print(f"\n1-3. Frida bypass.js로 재시작...")
            bypass_path = os.path.join("dynamic_analysis", "bypass.js")
            
            if os.path.exists(bypass_path):
                try:
                    print(f"   Frida로 {package_name} spawn 중 (bypass)...")
                    
                    # Frida CLI 명령어로 실행
                    frida_cmd = f'frida -U -f {package_name} -l {bypass_path}'
                    
                    # 백그라운드 프로세스로 실행
                    frida_process = subprocess.Popen(
                        frida_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    print(f"   ✓ bypass.js 실행 완료 (PID: {frida_process.pid})")
                    print(f"   Java 런타임 초기화 대기 중 (10초)...")
                    self.frida_process = frida_process  # 프로세스 유지
                    time.sleep(10)  # Java 런타임 초기화 대기
                    
                except Exception as e:
                    print(f"   ⚠ bypass.js 실행 실패: {str(e)[:100]}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"   ⚠ bypass.js 파일을 찾을 수 없습니다: {bypass_path}")
            
            # 2. 분석 진행 중 대기 (로그 수집 시간 증가)
            print(f"\n2. 분석 진행 중...")
            time.sleep(5)
            
            # 2-1. 액티비티 자동 실행
            print(f"\n2-1. 액티비티 실행 중...")
            print(f"   발견된 액티비티: {len(mobsf_activities) if mobsf_activities else 0}개")
            
            if mobsf_activities:
                for i, activity in enumerate(mobsf_activities[:5]):  # 최대 5개 실행
                    try:
                        print(f"   [{i+1}/{min(5, len(mobsf_activities))}] 실행: {activity}")
                        
                        # MobSF API로 액티비티 실행
                        activity_url = f"{mobsf_url}/api/v1/android/start_activity"
                        
                        # 전체 패키지명 포함된 액티비티 이름 생성
                        if activity.startswith('.'):
                            full_activity = f"{package_name}{activity}"
                        elif '.' not in activity:
                            full_activity = f"{package_name}.{activity}"
                        else:
                            full_activity = activity
                        
                        activity_data = {
                            "hash": file_hash,
                            "activity": full_activity
                        }
                        
                        result = requests.post(
                            activity_url,
                            headers=headers,
                            data=activity_data,
                            timeout=10
                        )
                        
                        print(f"      API URL: {activity_url}")
                        print(f"      Activity: {full_activity}")
                        print(f"      Status Code: {result.status_code}")
                        print(f"      Response: {result.text}")
                        
                        if result.status_code == 200:
                            print(f"      ✓ 성공")
                            
                            # ResultActivity인 경우 "치료하기" 버튼 클릭
                            if 'ResultActivity' in full_activity:
                                time.sleep(3)  # 화면 완전 로드 대기
                                print(f"      '치료하기' 버튼 클릭 시도...")
                                
                                try:
                                    # UI Automator로 화면 덤프
                                    dump_cmd = f'{self.adb_path} -s {self.device_name} shell uiautomator dump'
                                    subprocess.run(dump_cmd, shell=True, timeout=10, capture_output=True)
                                    
                                    # XML 파일 가져오기
                                    pull_cmd = f'{self.adb_path} -s {self.device_name} shell cat /sdcard/window_dump.xml'
                                    xml_result = subprocess.run(pull_cmd, shell=True, timeout=10, capture_output=True, text=True)
                                    
                                    if xml_result.returncode == 0:
                                        xml_content = xml_result.stdout
                                        
                                        # "치료하기" 텍스트 찾기
                                        import re
                                        pattern = r'text="치료하기"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"'
                                        match = re.search(pattern, xml_content)
                                        
                                        if match:
                                            x1, y1, x2, y2 = map(int, match.groups())
                                            # 중앙 좌표 계산
                                            center_x = (x1 + x2) // 2
                                            center_y = (y1 + y2) // 2
                                            
                                            print(f"      '치료하기' 버튼 발견: ({center_x}, {center_y})")
                                            
                                            # 클릭
                                            tap_cmd = f'{self.adb_path} -s {self.device_name} shell input tap {center_x} {center_y}'
                                            tap_result = subprocess.run(tap_cmd, shell=True, timeout=5, capture_output=True)
                                            
                                            if tap_result.returncode == 0:
                                                print(f"      ✓ 버튼 클릭 완료")
                                                time.sleep(2)
                                            else:
                                                print(f"      ⚠ 클릭 실패")
                                        else:
                                            print(f"      ⚠ '치료하기' 버튼을 찾을 수 없음")
                                    else:
                                        print(f"      ⚠ UI 덤프 실패")
                                        
                                except Exception as e:
                                    print(f"      ⚠ 버튼 클릭 오류: {str(e)[:50]}")
                        else:
                            print(f"      ⚠ 실패")
                        
                        time.sleep(3)  # 각 액티비티 실행 후 대기
                        
                    except Exception as e:
                        print(f"      ⚠ 오류: {str(e)[:50]}")
            
            # 추가 대기 (자동 실행 후 로그 수집)
            print(f"\n2-2. 추가 모니터링 중 (10초)...")
            time.sleep(10)
            
            # 2-3. Frida 로그 및 모니터링 결과 수집
            print(f"\n2-3. Frida 로그 및 모니터링 결과 수집...")
            
            # Frida API Monitor 출력 수집
            try:
                api_monitor_url = f"{mobsf_url}/api/v1/frida/api_monitor"
                api_monitor_data = {"hash": file_hash}
                
                api_monitor_response = requests.post(
                    api_monitor_url,
                    headers=headers,
                    data=api_monitor_data,
                    timeout=10
                )
                
                if api_monitor_response.status_code == 200:
                    api_monitor_result = api_monitor_response.json()
                    print(f"   ✓ API Monitor 결과 수집 완료")
                    
                    # API Monitor 결과 저장
                    api_monitor_file = f"mobsf_api_monitor_{file_hash}.json"
                    with open(api_monitor_file, "w", encoding="utf-8") as f:
                        json.dump(api_monitor_result, f, indent=2, ensure_ascii=False)
                    print(f"      저장: {api_monitor_file}")
                else:
                    print(f"   ⚠ API Monitor 수집 실패: {api_monitor_response.status_code}")
            except Exception as e:
                print(f"   ⚠ API Monitor 수집 중 오류: {str(e)[:50]}")
            
            # Frida Logs 수집
            try:
                frida_logs_url = f"{mobsf_url}/api/v1/frida/logs"
                frida_logs_data = {"hash": file_hash}
                
                frida_logs_response = requests.post(
                    frida_logs_url,
                    headers=headers,
                    data=frida_logs_data,
                    timeout=10
                )
                
                if frida_logs_response.status_code == 200:
                    frida_logs_result = frida_logs_response.json()
                    print(f"   ✓ Frida Logs 수집 완료")
                    
                    # Frida Logs 저장
                    frida_logs_file = f"mobsf_frida_logs_{file_hash}.json"
                    with open(frida_logs_file, "w", encoding="utf-8") as f:
                        json.dump(frida_logs_result, f, indent=2, ensure_ascii=False)
                    print(f"      저장: {frida_logs_file}")
                else:
                    print(f"   ⚠ Frida Logs 수집 실패: {frida_logs_response.status_code}")
            except Exception as e:
                print(f"   ⚠ Frida Logs 수집 중 오류: {str(e)[:50]}")
            
            # Runtime Dependencies 수집
            try:
                dependencies_url = f"{mobsf_url}/api/v1/frida/get_dependencies"
                dependencies_data = {"hash": file_hash}
                
                dependencies_response = requests.post(
                    dependencies_url,
                    headers=headers,
                    data=dependencies_data,
                    timeout=10
                )
                
                if dependencies_response.status_code == 200:
                    print(f"   ✓ Runtime Dependencies 수집 완료")
                    print(f"      응답: {dependencies_response.json()}")
                else:
                    print(f"   ⚠ Runtime Dependencies 수집 실패: {dependencies_response.status_code}")
            except Exception as e:
                print(f"   ⚠ Runtime Dependencies 수집 중 오류: {str(e)[:50]}")
            
            # 3. 동적 분석 중지 (결과 생성)
            print(f"\n3. 동적 분석 중지 중...")
            stop_url = f"{mobsf_url}/api/v1/dynamic/stop_analysis"
            stop_data = {
                "hash": file_hash
            }
            
            stop_response = requests.post(
                stop_url,
                headers=headers,
                data=stop_data,
                timeout=30
            )
            
            if stop_response.status_code == 200:
                print(f"✓ 동적 분석 중지 완료")
                stop_result = stop_response.json()
                print(f"   결과: {stop_result}")
            else:
                print(f"⚠ 분석 중지 응답: {stop_response.status_code}")
                print(f"   응답: {stop_response.text}")
            
            # 4. 동적 분석 결과 가져오기
            print(f"\n4. 분석 결과 수집 중...")
            report_url = f"{mobsf_url}/api/v1/dynamic/report_json"
            report_data = {
                "hash": file_hash
            }
            
            report_response = requests.post(
                report_url,
                headers=headers,
                data=report_data,
                timeout=30
            )
            
            if report_response.status_code == 200:
                print(f"✓ 분석 결과 수집 완료")
                dynamic_result = report_response.json()
                
                # JSON 결과 저장
                result_file = f"mobsf_dynamic_{file_hash}.json"
                with open(result_file, "w", encoding="utf-8") as f:
                    json.dump(dynamic_result, f, indent=2, ensure_ascii=False)
                print(f"   JSON 저장: {result_file}")
                
                # PDF 결과 저장
                print(f"\n5. PDF 리포트 다운로드 중...")
                pdf_url = f"{mobsf_url}/api/v1/dynamic/report_pdf"
                pdf_data = {
                    "hash": file_hash
                }
                
                try:
                    pdf_response = requests.post(
                        pdf_url,
                        headers=headers,
                        data=pdf_data,
                        timeout=60
                    )
                    
                    if pdf_response.status_code == 200 and pdf_response.content:
                        pdf_file = f"mobsf_dynamic_{file_hash}.pdf"
                        with open(pdf_file, "wb") as f:
                            f.write(pdf_response.content)
                        print(f"   ✓ PDF 저장: {pdf_file}")
                    else:
                        print(f"   ⚠ PDF 다운로드 실패: {pdf_response.status_code}")
                        if pdf_response.text:
                            print(f"   응답: {pdf_response.text[:200]}")
                except Exception as e:
                    print(f"   ⚠ PDF 다운로드 오류: {str(e)[:50]}")
                
                return "success", []
            else:
                print(f"⚠ 결과 수집 실패: {report_response.status_code}")
                print(f"   응답: {report_response.text}")
                return "success", []  # 분석은 완료되었으므로 success
                
        except ImportError:
            print("✗ requests 라이브러리가 필요합니다: pip install requests")
            return "error", []
        except requests.exceptions.ConnectionError:
            print(f"✗ MobSF 연결 실패. MobSF가 실행 중인지 확인하세요.")
            return "error", []
        except Exception as e:
            print(f"✗ MobSF 동적 분석 실패: {e}")
            import traceback
            traceback.print_exc()
            return "error", []

    #API6. 로그캣으로 로그 전체 가져오기.
    def extract_logcat(self, output_file="full_logcat_result.txt"):
        print("Logcat 데이터 수집를 수집중입니다.")

        if not getattr(self, 'device_name', None):
            print("에뮬레이터 연결이 필요합니다.")
            return "emulator name not set"

        try:
            print(f"{self.device_name}에서 로그를 추출합니다.")
            # -d: 현재까지의 로그만 덤프하고 종료 (실시간 스트리밍 방지)
            # -v brief: 간결한 형식
            command = [self.adb_path, "-s", self.device_name, "logcat", "-d", "-v", "brief"]

            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='ignore', check=False)
            raw_logs = result.stdout

            if result.returncode == 0 and raw_logs:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(raw_logs)
                print(f"   ✓ 로그 수집 완료: {len(raw_logs)} bytes")
                return raw_logs
            elif result.returncode != 0:
                print(f"   ⚠ Logcat 반환 코드: {result.returncode}")
                print(f"   stderr: {result.stderr[:200]}")
                return "logcat error"
            else:
                print("   수집된 로그가 비어 있습니다.")
                return "empty logs"

        except Exception as e:
            error_message = f"Logcat 추출 중 오류: {str(e)[:100]}"
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
    def result_json(self, filtered_results, detected_tags, mode, apk_file_name, dumped_dex_list, analyzed_dex_list, dumped_dex_path=None):
        print(f"최종 결과를 JSON파일로 반환합니다.({mode})")

        dumped_count = len(dumped_dex_list) if dumped_dex_list else 0
        analyzed_count = len(analyzed_dex_list) if analyzed_dex_list else 0

        status = "detected" if detected_tags else "success"
        apk_name = os.path.splitext(os.path.basename(apk_file_name))[0]
        file_name = f"analyzed_{apk_name}_{mode}.txt"

        try:
            with open(file_name, "w", encoding="utf-8") as f:
                if isinstance(filtered_results, list):
                    f.write("\n".join(map(str, filtered_results)))
                else:
                    f.write(str(filtered_results))
            print(f"로그 파일 생성 완료: {file_name}")
        except Exception as e:
            print(f"파일 생성 중 오류 발생: {e}")

        result_schema = {
        "metadata": {
            "analyzer": "DeepGuard_Dynamic_Engine",
            "target_app": apk_name,
            "mode": mode
        },
        "analysis_summary": {
            "status": status,
            "anti_analysis_detected": detected_tags,
            "dex_extraction": {
                "dumped_count": len(dumped_dex_list),
                "analyzed_count": len(analyzed_dex_list),
                "efficiency": f"{(analyzed_count/dumped_count*100) if dumped_count > 0 else 0:.1f}%"
            }
        },
        "threat_details": {
            "match_count": len(filtered_results),
            "matches": filtered_results,
            "is_encrypted_payload": True
        },
        "artifacts": {
            "dump_path": dumped_dex_path,
            "log_file": file_name
        }
    }

        return json.dumps(result_schema, indent=4, ensure_ascii=False)

    #컨트롤러
    def dynamic_controller(self, apk_path, run_id, file_hash, mode="speedy"):

        #API1 실행
        evidence, interpretation = self.receive_static_result(run_id)
        if not evidence:
            return {"error": "Static data not found"}

        #API2 실행
        plan = self.parse_static_result(evidence, interpretation, mode)

        if plan["action"] == "stop":
            print(f"분석 중단. {plan.get('reason')}")
            return {"msg": f"정적 분석결과에 의해 중단. {plan.get('reason')}"}

        # 패키지명 추출
        package_name = plan.get("package_name")
        
        if not file_hash:
            print("✗ file_hash가 제공되지 않았습니다.")
            return {"error": "file_hash is required"}
        
        print(f"제공된 Hash: {file_hash}")
        print(f"패키지명: {package_name}")

        #API3 함수 실행
        status, detected_tags = self.dynamic_environment(file_hash, package_name, run_id, hints=plan.get("hints"))

        #API4 실행
        reallogs = self.extract_logcat()
        filtered_logs = self.regex_filtering(reallogs, interpretation, mode)
        # subprocess.run([self.adb_path, "emu", "kill"], shell=False)
        
        #API5 실행 - dump_path 안전하게 처리
        if os.path.exists(self.output_dir):
            try:
                dir_contents = os.listdir(self.output_dir)
                if dir_contents:
                    dump_path = self.output_dir
                    dumped_list = dir_contents
                    analyzed_list = [f for f in dumped_list if f.endswith(".dex")]
                else:
                    dump_path = None
                    dumped_list = []
                    analyzed_list = []
            except Exception as e:
                print(f"dump 폴더 읽기 실패: {e}")
                dump_path = None
                dumped_list = []
                analyzed_list = []
        else:
            dump_path = None
            dumped_list = []
            analyzed_list = []

        final_json = self.result_json(
            filtered_results=filtered_logs,
            detected_tags=detected_tags,
            mode=mode,
            apk_file_name=apk_path,
            dumped_dex_list=dumped_list,
            analyzed_dex_list=analyzed_list,
            dumped_dex_path=dump_path,
        )
        result_dir = os.path.join(os.getcwd(), "out_b")
        if not os.path.exists(result_dir): os.makedirs(result_dir)

        result_file = os.path.join(result_dir, f"dynamic_report_{run_id}.json")
        with open(result_file, "w", encoding="utf-8") as f:
            f.write(final_json)

        print("\n최종 결과물")
        print(final_json)
        return final_json


#데모파일 테스트
if __name__ == "__main__":
    analyzer = deepguard_dynamic_analyzer(mobsf_emulator="host.docker.internal:5555")

    test_run_id = "test_analysis_report_001"
    apk_file_name = "sample.apk"

    base_path = os.path.join(os.getcwd(), "out_runs_b", test_run_id)
    os.makedirs(base_path, exist_ok=True)

    mock_evidence = {
        "evidence": {
            "apk.info": {
                "package_name": "com.ldjSxw.heBbQd",
                "md5": "f90f81f7b47ca73de0e5aa5aaeba6735"
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
        # 정적 분석에서 받은 hash를 전달
        test_hash = "f90f81f7b47ca73de0e5aa5aaeba6735"
        
        final_report = analyzer.dynamic_controller(
            apk_path=apk_file_name,
            run_id=test_run_id,
            file_hash=test_hash,
            mode="exact"
        )

        print("\n" + "=" * 50)
        print("최종 동적 분석 리포트 결과")
        print("=" * 50)
        print(final_report)

    except Exception as e:
        print(f"\n[실행 중단] 동적 분석 중 오류 발생: {e}")
