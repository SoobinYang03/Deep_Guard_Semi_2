# Static Analysis - APK 분석 및 DEX 복호화 도구

Android APK 정적 분석, DEX 파일 복호화, APK 재패키징을 위한 자동화 도구 모음입니다.

## 📋 목차

- [기능](#-기능)
- [프로젝트 구조](#-프로젝트-구조)
- [설치](#-설치)
- [사용 방법](#-사용-방법)
- [테스트](#-테스트)

## ✨ 기능

### 1. MobSF 정적 분석
- MobSF API를 통한 APK 자동 업로드 및 분석
- JSON/PDF 형식의 분석 리포트 다운로드
- 환경 변수를 통한 API 키 관리

### 2. DEX 브루트포스 복호화
- MobSF 리포트에서 추출한 문자열 기반 키 후보 생성
- 다중 암호화 알고리즘 지원:
  - AES (128/192/256-bit, ECB/CBC/CTR/CFB 모드)
  - DES, 3DES
  - Blowfish
  - RC4
  - XOR
- 자동 DEX 파일 검증 및 복호화

### 3. APK 재패키징
- APK 재압축 및 자동 서명

## 📁 프로젝트 구조

```
static_analysis/
├── src/                          # 소스 코드
│   ├── mobsf.py                 # MobSF API 클라이언트
│   ├── dex_bruteforce_decryptor.py  # DEX 복호화
│   ├── apk_extractor.py         # APK 압축 해제
│   ├── apk_packer.py            # APK 재패키징 및 서명
│   ├── apk_repackager.py        # 전체 워크플로우 관리
│   └── logger_config.py         # 로깅 설정
├── tests/                        # 테스트 코드
│   └── test_decrypt.py          # pytest 테스트
├── output/                       # 출력 디렉토리
│   ├── report/                  # MobSF 리포트
│   ├── extracted/               # 압축 해제된 APK
│   └── decrypted/               # 재패키징된 APK
└── README.md                    
```

## 🔧 설치

### 요구사항
- Python 3.8 이상
- MobSF 서버 (로컬 또는 원격)
- Android SDK Build Tools (APK 서명용, 선택사항)

### 의존성 설치

```bash
pip install -r requirements.txt
```

**필수 패키지:**
- `requests` - HTTP 클라이언트
- `pycryptodome` - 암호화/복호화
- `python-dotenv` - 환경 변수 관리
- `pytest` - 테스트 프레임워크

### 환경 변수 설정

프로젝트 루트에 `.env` 파일 생성:

```env
MOBSF=your_mobsf_api_key_here
MOBSF_URL=http://127.0.0.1:8000
```

## 🚀 사용 방법

### 통합 파이프라인

**main.py를 사용한 전체 자동화**

모든 단계를 자동으로 실행:

```bash
cd src
python main.py /path/to/apk
```

**테스트 모드 (DEX 복호화 시 테스트 리포트 사용):**

```bash
python main.py /path/to/apk --test
```
- MobSF 분석은 정상 실행
- DEX 복호화 시에만 `static_analysis/output/mobsf_report_test.json` 사용
- 복호화 테스트에 유용
- 테스트 시 복호화 작업 빨리 끝남.


**출력:**
- MobSF 리포트: `output/report/mobsf_report_<hash>_<timestamp>.json`
- 압축 해제: `output/extracted/<apk_name>_extracted/`
- 복호화된 DEX: `output/extracted/<apk_name>_extracted/decrypted_<algorithm>_<filename>.dex`
- 최종 APK: `output/decrypted/<apk_name>_repackaged_signed.apk`

---

### 개별 모듈 실행 (단계별)

#### 전체 워크플로우 (권장)

**1단계: MobSF 정적 분석**
```bash
cd src
python mobsf.py /path/to/apk
```
출력: `output/report/mobsf_report_<hash>_<timestamp>.json`

**2단계: APK 압축 해제**
```bash
python apk_extractor.py /path/to/apk
```
출력: `output/extracted/sample_extracted/`

**3단계: DEX 파일 복호화**
```bash
python dex_bruteforce_decryptor.py /path/to/{보고서 파일}.json  /path/to/output/extracted/{apk 압축해제 경로}
```
출력: `output/extracted/sample_extracted/decrypted_<알고리즘>_<파일명>.dex`

**4단계: APK 재패키징 및 서명**
```bash
python apk_packer.py /path/to/output/extracted/{apk 압축 해제 경로}
```
출력: `output/decrypted/sample_repackaged_signed.apk`

---

## 🧪 테스트

### pytest 실행

```bash
cd tests
python test_decrypt.py
```

또는

```bash
pytest test_decrypt.py -v -s
```

### 테스트 내용

1. **초기화 테스트** - Decryptor 정상 초기화 확인
2. **DEX 파일 탐색** - DEX 파일 자동 검색
3. **키 후보 생성** - MobSF 리포트에서 키 추출
4. **올바른 키 복호화** - 정상 키로 복호화 성공
5. **잘못된 키 복호화** - 잘못된 키로 복호화 실패 확인
6. **결과 요약** - 전체 복호화 결과 검증

## 📝 주요 기능 상세

### MobSF 분석 (mobsf.py)

**클래스:** `MobSFAnalyzer`

```python
from mobsf import MobSFAnalyzer

analyzer = MobSFAnalyzer(api_key="your_key", server_url="http://localhost:8000")
results = analyzer.analyze_apk("sample.apk")
```

**메서드:**
- `upload_apk(apk_path)` - APK 업로드
- `scan_apk(file_name, scan_hash)` - 정적 분석 실행
- `download_report(scan_hash, output_dir)` - 리포트 다운로드
- `analyze_apk(apk_path, output_dir)` - 전체 프로세스

### DEX 복호화 (dex_bruteforce_decryptor.py)

**클래스:** `DexBruteforceDecryptor`

```python
from dex_bruteforce_decryptor import DexBruteforceDecryptor

decryptor = DexBruteforceDecryptor("mobsf_report.json", "dex_dir/")
results = decryptor.run()
```

**메서드:**
- `load_strings_from_report()` - 리포트에서 문자열 추출
- `find_dex_files()` - DEX 파일 검색
- `generate_key_candidates()` - 키 후보 생성
- `decrypt_dex_file(dex_path)` - DEX 복호화
- `is_valid_dex(data)` - DEX 파일 검증

**지원 암호화:**
- AES: ECB, CBC, CTR, CFB (128/192/256-bit)
- DES: ECB, CBC
- 3DES: ECB, CBC (128/192-bit)
- Blowfish: ECB, CBC (128/256-bit)
- RC4: 128/256-bit
- XOR

### APK 재패키징 (apk_repackager.py)

**클래스:** `ApkRepackager`

```python
from apk_repackager import ApkRepackager

repackager = ApkRepackager("sample.apk")
results = repackager.process_full_workflow("mobsf_report.json", sign=True)
```

### 통합 파이프라인 (main.py)

**클래스:** `StaticAnalysisPipeline`

전체 파이프라인을 통합 관리하는 메인 클래스:

```python
from main import StaticAnalysisPipeline

pipeline = StaticAnalysisPipeline(
    apk_path="sample.apk",
    mobsf_api_key="your_key",  # 선택사항
    mobsf_url="http://localhost:8000"  # 선택사항
)

results = pipeline.run_full_pipeline(test_mode=False)
```

**워크플로우:**
1. MobSF 정적 분석
2. APK 압축 해제
3. DEX 파일 복호화 (test_mode=True일 때 테스트 리포트 사용)
4. APK 재패키징 및 자동 서명