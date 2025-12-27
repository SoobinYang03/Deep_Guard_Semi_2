"""
MobSF API Integration Module
APK 업로드, 스캔, 리포트 다운로드 기능 제공
"""

import requests
import json
import logging
import os
import time
import argparse
from pathlib import Path
from typing import Dict, Optional
from dotenv import load_dotenv

from logger_config import LoggerConfig


class MobSFAnalyzer:
    """MobSF API를 활용한 APK 분석 클래스"""
    
    def __init__(self, server_url: str = "http://localhost:8000", api_key: str = ""):
        """
        MobSF 분석기 초기화
        
        Args:
            server_url: MobSF 서버 URL (기본값: http://localhost:8000)
            api_key: MobSF API 키
        """
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.headers = {'Authorization': api_key} if api_key else {}
        
        # 로깅 설정
        self.logger = LoggerConfig.get_logger(__name__, level=logging.DEBUG)
        
        self.logger.info(f"MobSF Analyzer 초기화 완료")
        self.logger.info(f"서버 URL: {self.server_url}")
        self.logger.info(f"API 키 설정 여부: {'예' if api_key else '아니오'}")
        
    
    def upload_apk(self, apk_path: str) -> Optional[Dict]:
        """
        APK 파일을 MobSF 서버에 업로드
        
        Args:
            apk_path: 업로드할 APK 파일 경로
            
        Returns:
            업로드 결과 딕셔너리 (hash 포함) 또는 None
        """
        
        self.logger.info("APK 업로드 시작")
        
        # 파일 존재 확인
        if not os.path.exists(apk_path):
            self.logger.error(f"APK 파일을 찾을 수 없습니다: {apk_path}")
            return None
        
        file_size = os.path.getsize(apk_path)
        self.logger.info(f"APK 파일 경로: {apk_path}")
        self.logger.info(f"APK 파일 크기: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
        
        url = f"{self.server_url}/api/v1/upload"
        self.logger.info(f"업로드 URL: {url}")
        
        try:
            with open(apk_path, 'rb') as f:
                files = {'file': (os.path.basename(apk_path), f, 'application/octet-stream')}
                self.logger.debug(f"파일 업로드 요청 전송 중...")
                
                start_time = time.time()
                response = requests.post(url, files=files, headers=self.headers, timeout=300)
                elapsed_time = time.time() - start_time
                
                self.logger.info(f"응답 상태 코드: {response.status_code}")
                self.logger.info(f"업로드 소요 시간: {elapsed_time:.2f}초")
                
                if response.status_code == 200:
                    result = response.json()
                    self.logger.info("✓ APK 업로드 성공!")
                    self.logger.info(f"파일 해시: {result.get('hash', 'N/A')}")
                    self.logger.info(f"파일명: {result.get('file_name', 'N/A')}")
                    self.logger.info(f"스캔 타입: {result.get('scan_type', 'N/A')}")
                    self.logger.debug(f"전체 응답: {json.dumps(result, indent=2, ensure_ascii=False)}")
                    return result
                else:
                    self.logger.error(f"✗ 업로드 실패 (상태 코드: {response.status_code})")
                    self.logger.error(f"응답 내용: {response.text}")
                    return None
                    
        except requests.exceptions.Timeout:
            self.logger.error("✗ 업로드 타임아웃 발생 (300초 초과)")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"✗ 업로드 중 요청 오류 발생: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"✗ 업로드 중 예상치 못한 오류 발생: {str(e)}", exc_info=True)
            return None
    
    def scan_apk(self, file_hash: str, scan_type: str = "apk") -> Optional[Dict]:
        """
        업로드된 APK 스캔 수행
        
        Args:
            file_hash: 업로드된 파일의 해시값
            scan_type: 스캔 타입 (기본값: "apk")
            
        Returns:
            스캔 결과 딕셔너리 또는 None
        """
        
        self.logger.info("APK 스캔 시작")
        
        url = f"{self.server_url}/api/v1/scan"
        self.logger.info(f"스캔 URL: {url}")
        self.logger.info(f"파일 해시: {file_hash}")
        self.logger.info(f"스캔 타입: {scan_type}")
        
        data = {
            'hash': file_hash,
            'scan_type': scan_type,
            're_scan': 0  # 재스캔 여부 (0: 새 스캔, 1: 재스캔)
        }
        
        self.logger.debug(f"스캔 요청 데이터: {json.dumps(data, indent=2)}")
        
        try:
            self.logger.info("스캔 요청 전송 중...")
            start_time = time.time()
            
            response = requests.post(url, data=data, headers=self.headers, timeout=600)
            
            elapsed_time = time.time() - start_time
            self.logger.info(f"응답 상태 코드: {response.status_code}")
            self.logger.info(f"스캔 소요 시간: {elapsed_time:.2f}초")
            
            if response.status_code == 200:
                result = response.json()
                self.logger.info("✓ 스캔 완료!")
                
                # 주요 스캔 결과 로깅
                if 'file_name' in result:
                    self.logger.info(f"파일명: {result['file_name']}")
                if 'size' in result:
                    self.logger.info(f"파일 크기: {result['size']}")
                if 'md5' in result:
                    self.logger.info(f"MD5: {result['md5']}")
                if 'app_name' in result:
                    self.logger.info(f"앱 이름: {result['app_name']}")
                if 'package_name' in result:
                    self.logger.info(f"패키지명: {result['package_name']}")
                if 'version_name' in result:
                    self.logger.info(f"버전: {result['version_name']}")
                
                self.logger.debug(f"전체 스캔 결과 키: {list(result.keys())}")
                
                return result
            else:
                self.logger.error(f"✗ 스캔 실패 (상태 코드: {response.status_code})")
                self.logger.error(f"응답 내용: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            self.logger.error("✗ 스캔 타임아웃 발생 (600초 초과)")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"✗ 스캔 중 요청 오류 발생: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"✗ 스캔 중 예상치 못한 오류 발생: {str(e)}", exc_info=True)
            return None
    
    def download_report(self, file_hash: str, output_dir: Optional[str] = None, 
                       report_format: str = "pdf") -> Optional[str]:
        """
        스캔 리포트 다운로드
        
        Args:
            file_hash: 스캔된 파일의 해시값
            output_dir: 리포트 저장 디렉토리 (기본값: None - 프로젝트 루트의 output/report 사용)
            report_format: 리포트 형식 ("pdf" 또는 "json", 기본값: "pdf")
            
        Returns:
            저장된 리포트 파일 경로 또는 None
        """
        
        self.logger.info("리포트 다운로드 시작")
        
        # 출력 디렉토리 설정 (기본값: src 폴더의 output/report)
        if output_dir is None:
            output_dir = str(Path(__file__).parent.parent / 'output' / 'report')
        
        # 출력 디렉토리 생성
        os.makedirs(output_dir, exist_ok=True)
        self.logger.info(f"리포트 저장 디렉토리: {output_dir}")
        self.logger.info(f"리포트 형식: {report_format.upper()}")
        
        if report_format.lower() == "pdf":
            url = f"{self.server_url}/api/v1/download_pdf"
            file_extension = "pdf"
        elif report_format.lower() == "json":
            url = f"{self.server_url}/api/v1/report_json"
            file_extension = "json"
        else:
            self.logger.error(f"지원하지 않는 리포트 형식: {report_format}")
            return None
        
        self.logger.info(f"다운로드 URL: {url}")
        self.logger.info(f"파일 해시: {file_hash}")
        
        data = {'hash': file_hash}
        
        try:
            self.logger.info("리포트 다운로드 요청 전송 중...")
            start_time = time.time()
            
            response = requests.post(url, data=data, headers=self.headers, 
                                   stream=True, timeout=300)
            
            elapsed_time = time.time() - start_time
            self.logger.info(f"응답 상태 코드: {response.status_code}")
            
            if response.status_code == 200:
                # 파일명 생성
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"mobsf_report_{file_hash[:8]}_{timestamp}.{file_extension}"
                filepath = os.path.join(output_dir, filename)
                
                self.logger.info(f"리포트 파일명: {filename}")
                
                # 파일 저장
                total_size = 0
                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            total_size += len(chunk)
                
                download_time = time.time() - start_time
                self.logger.info("✓ 리포트 다운로드 완료!")
                self.logger.info(f"저장 경로: {os.path.abspath(filepath)}")
                self.logger.info(f"파일 크기: {total_size:,} bytes ({total_size / 1024:.2f} KB)")
                self.logger.info(f"다운로드 시간: {download_time:.2f}초")
                
                return filepath
            else:
                self.logger.error(f"✗ 리포트 다운로드 실패 (상태 코드: {response.status_code})")
                self.logger.error(f"응답 내용: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            self.logger.error("✗ 리포트 다운로드 타임아웃 발생 (300초 초과)")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"✗ 리포트 다운로드 중 요청 오류 발생: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"✗ 리포트 다운로드 중 예상치 못한 오류 발생: {str(e)}", exc_info=True)
            return None
    
    def analyze_apk(self, apk_path: str, output_dir: Optional[str] = None, 
                   download_pdf: bool = True, download_json: bool = True) -> Dict:
        """
        APK 전체 분석 프로세스 실행 (업로드 → 스캔 → 리포트 다운로드)
        
        Args:
            apk_path: 분석할 APK 파일 경로
            output_dir: 리포트 저장 디렉토리 (기본값: None - 프로젝트 루트의 output/report 사용)
            download_pdf: PDF 리포트 다운로드 여부
            download_json: JSON 리포트 다운로드 여부
            
        Returns:
            분석 결과 딕셔너리
        """
        
        self.logger.info("MobSF APK 전체 분석 프로세스 시작")
        
        # 출력 디렉토리 설정 (기본값: src 폴더의 output/report)
        if output_dir is None:
            output_dir = str(Path(__file__).parent.parent / 'output' / 'report')
        
        self.logger.info("MobSF APK 전체 분석 프로세스 시작")
        
        start_time = time.time()
        result = {
            'success': False,
            'apk_path': apk_path,
            'upload_result': None,
            'scan_result': None,
            'pdf_report_path': None,
            'json_report_path': None,
            'errors': []
        }
        
        # 1. APK 업로드
        upload_result = self.upload_apk(apk_path)
        if not upload_result:
            error_msg = "APK 업로드 실패"
            self.logger.error(f"✗ {error_msg}")
            result['errors'].append(error_msg)
            return result
        
        result['upload_result'] = upload_result
        file_hash = upload_result.get('hash')
        
        if not file_hash:
            error_msg = "업로드 결과에서 파일 해시를 찾을 수 없음"
            self.logger.error(f"✗ {error_msg}")
            result['errors'].append(error_msg)
            return result
        
        # 2. APK 스캔
        scan_result = self.scan_apk(file_hash)
        if not scan_result:
            error_msg = "APK 스캔 실패"
            self.logger.error(f"✗ {error_msg}")
            result['errors'].append(error_msg)
            return result
        
        result['scan_result'] = scan_result
        
        # 3. 리포트 다운로드
        if download_pdf:
            pdf_path = self.download_report(file_hash, output_dir, "pdf")
            if pdf_path:
                result['pdf_report_path'] = pdf_path
            else:
                error_msg = "PDF 리포트 다운로드 실패"
                self.logger.warning(f"⚠ {error_msg}")
                result['errors'].append(error_msg)
        
        if download_json:
            json_path = self.download_report(file_hash, output_dir, "json")
            if json_path:
                result['json_report_path'] = json_path
            else:
                error_msg = "JSON 리포트 다운로드 실패"
                self.logger.warning(f"⚠ {error_msg}")
                result['errors'].append(error_msg)
        
        # 전체 프로세스 완료
        total_time = time.time() - start_time
        result['success'] = True
        
        
        self.logger.info("✓ MobSF APK 분석 프로세스 완료!")
        
        self.logger.info(f"총 소요 시간: {total_time:.2f}초")
        self.logger.info(f"APK 파일: {apk_path}")
        self.logger.info(f"파일 해시: {file_hash}")
        if result['pdf_report_path']:
            self.logger.info(f"PDF 리포트: {result['pdf_report_path']}")
        if result['json_report_path']:
            self.logger.info(f"JSON 리포트: {result['json_report_path']}")
        if result['errors']:
            self.logger.warning(f"경고 사항: {len(result['errors'])}개")
            for error in result['errors']:
                self.logger.warning(f"  - {error}")
        
        
        return result


def main():
    """사용 예제"""
    # .env 파일에서 환경 변수 로드 (프로젝트 루트의 .env 파일)
    env_path = Path(__file__).parent.parent.parent / '.env'
    load_dotenv(dotenv_path=env_path)
    
    # .env 파일 경로 확인
    if not env_path.exists():
        print(f"⚠ .env 파일을 찾을 수 없습니다: {env_path}")
        print(f"  프로젝트 루트에 .env 파일을 생성하고 MOBSF=your_api_key 를 추가하세요.")
    else:
        print(f"✓ .env 파일 로드됨: {env_path}")
    
    # 커맨드라인 인자 파싱
    parser = argparse.ArgumentParser(
        description='MobSF API를 활용한 APK 분석 도구',
        epilog='사용 예제: python mobsf.py sample.apk'
    )
    parser.add_argument('apk_path', help='분석할 APK 파일 경로')
    args = parser.parse_args()
    
    # MobSF 서버 설정
    MOBSF_SERVER = "http://localhost:8000"
    MOBSF_API_KEY = os.getenv("MOBSF", "")  # .env 파일에서 API 키 읽기
    
    # 리포트 저장 디렉토리 (src 폴더의 output/report)
    OUTPUT_DIR = str(Path(__file__).parent.parent / 'output' / 'report')
    
    # MobSF Analyzer 초기화
    analyzer = MobSFAnalyzer(server_url=MOBSF_SERVER, api_key=MOBSF_API_KEY)
    
    # 전체 분석 프로세스 실행
    result = analyzer.analyze_apk(
        apk_path=args.apk_path,
        output_dir=OUTPUT_DIR,
        download_pdf=True,
        download_json=True
    )
    
    # 결과 확인
    if result['success']:
        print("\n분석 성공!")
        print(f"PDF 리포트: {result['pdf_report_path']}")
        print(f"JSON 리포트: {result['json_report_path']}")
    else:
        print("\n분석 실패!")
        print(f"오류: {result['errors']}")


if __name__ == "__main__":
    main()
