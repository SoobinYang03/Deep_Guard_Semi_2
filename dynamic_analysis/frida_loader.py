import frida
import sys
import os
import time

# 덤프 파일 저장 경로
OUTPUT_DIR = "dumped_dex"

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# 스파이(JS)가 보낸 데이터를 받는 함수
def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print(f"[*] [Agent] {payload}")
        
        # DEX 덤프 데이터가 오면 파일로 저장
        if isinstance(payload, dict) and payload.get("type") == "dex_dump":
            ensure_dir(OUTPUT_DIR)
            file_name = os.path.join(OUTPUT_DIR, f"dump_{payload['addr']}.dex")
            
            if data:
                with open(file_name, "wb") as f:
                    f.write(data)
                print(f"[Success] DEX 덤프 저장 완료: {file_name}")
            else:
                print("[Error] 덤프 데이터가 비어있습니다.")
    elif message['type'] == 'error':
        print(f"[Error] {message['stack']}")

# 분석 실행 함수
def run_frida_analysis(package_name):
    print(f"[*] Frida 분석 시작: {package_name}")
    
    try:
        # USB 연결된 기기(에뮬레이터) 찾기
        device = frida.get_usb_device()
        print(f"[*] 디바이스 연결됨: {device}")

        # 앱 실행 (Spawn)
        print("[*] 앱 실행 중...")
        pid = device.spawn([package_name])
        session = device.attach(pid)
        
        # agent.js 파일 읽기
        current_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(current_dir, "agent.js"), "r", encoding="utf-8") as f:
            script_code = f.read()

        # 스크립트 주입
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        # 앱 메인 실행 (Resume)
        device.resume(pid)
        print("[*] 스크립트 주입 완료. 분석 대기 중...")
        
        # 10초 대기 후 종료
        time.sleep(30)
        print("[*] 분석 종료")
        
    except Exception as e:
        print(f"[!] 오류 발생: {e}")

if __name__ == "__main__":
    # 준기님이 공유한 SpyNote 패키지명
    TARGET_PKG = "in.titanium.cooked" 
    run_frida_analysis(TARGET_PKG)