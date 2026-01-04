"""
Static Analysis Main Entry Point
APK 정적 분석, DEX 복호화, 재패키징 통합 실행
"""

import sys
import os
import argparse
import logging
from pathlib import Path

from logger_config import LoggerConfig
from mobsf import MobSFAnalyzer
from apk_extractor import ApkExtractor
from dex_bruteforce_decryptor import DexBruteforceDecryptor
from apk_packer import ApkPacker


class StaticAnalysisPipeline:
    """
    APK 정적 분석 파이프라인 통합 실행 클래스
    """
    
    def __init__(self, apk_path: str, mobsf_api_key: str = None, mobsf_url: str = None):
        """
        초기화
        
        Args:
            apk_path: APK 파일 경로
            mobsf_api_key: MobSF API 키 (None이면 .env에서 로드)
            mobsf_url: MobSF 서버 URL (None이면 .env에서 로드)
        """
        self.apk_path = Path(apk_path)
        
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK 파일을 찾을 수 없습니다: {apk_path}")
        
        # 환경 변수 로드
        if mobsf_api_key is None or mobsf_url is None:
            from dotenv import load_dotenv
            load_dotenv()
            mobsf_api_key = mobsf_api_key or os.getenv("MOBSF", "")
            mobsf_url = mobsf_url or os.getenv("MOBSF_URL", "http://127.0.0.1:8000")
        
        self.mobsf_analyzer = MobSFAnalyzer(server_url=mobsf_url, api_key=mobsf_api_key)
        self.logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
        
        # 결과 저장용
        self.results = {
            'apk_path': str(self.apk_path),
            'mobsf_report': None,
            'extracted_dir': None,
            'decrypted_files': [],
            'repackaged_apk': None,
            'success': False
        }
    
    def run_full_pipeline(self, test_mode: bool = False) -> dict:
        """
        전체 파이프라인 실행
        
        Args:
            test_mode: 테스트 모드 (True면 미리 정의된 리포트 사용)
        
        Returns:
            결과 딕셔너리
        """
        self.logger.info("="*80)
        self.logger.info("APK 정적 분석 파이프라인 시작")
        if test_mode:
            self.logger.info("모드: 테스트 (복호화 시 테스트 리포트 사용)")
        self.logger.info("="*80)
        
        try:
            # 1. MobSF 정적 분석
            self.logger.info("\n[1/4] MobSF 정적 분석 실행 중...")
            mobsf_result = self.mobsf_analyzer.analyze_apk(str(self.apk_path))
            
            if mobsf_result and mobsf_result.get('success') and mobsf_result.get('json_report_path'):
                self.results['mobsf_report'] = mobsf_result['json_report_path']
                self.logger.info(f"✓ MobSF 리포트 생성: {mobsf_result['json_report_path']}")
            else:
                self.logger.error("✗ MobSF 분석 실패")
                if mobsf_result and mobsf_result.get('errors'):
                    for error in mobsf_result['errors']:
                        self.logger.error(f"  - {error}")
                return self.results
            
            # 2. APK 압축 해제
            self.logger.info("\n[2/4] APK 압축 해제 중...")
            extractor = ApkExtractor(str(self.apk_path))
            extract_dir = extractor.extract(force=True)
            self.results['extracted_dir'] = str(extract_dir)
            self.logger.info(f"✓ APK 압축 해제 완료: {extract_dir}")
            
            # 3. DEX 파일 복호화
            self.logger.info("\n[3/4] DEX 파일 복호화 시도 중...")
            
            # 테스트 모드일 때 테스트 리포트 사용
            if test_mode:
                test_report = Path(__file__).parent.parent / 'tests' / 'mobsf_report_test.json'
                if test_report.exists():
                    decrypt_report = str(test_report)
                    self.logger.info(f"테스트 모드: 테스트 리포트 사용 - {test_report}")
                else:
                    self.logger.warning(f"테스트 리포트를 찾을 수 없습니다: {test_report}")
                    self.logger.info("정상 MobSF 리포트로 복호화 진행")
                    decrypt_report = self.results['mobsf_report']
            else:
                decrypt_report = self.results['mobsf_report']
            
            decryptor = DexBruteforceDecryptor(
                decrypt_report,
                str(extract_dir)
            )
            
            # 문자열 로딩 및 DEX 파일 검색
            decryptor.load_strings_from_report()
            decryptor.find_dex_files()
            
            if not decryptor.dex_files:
                self.logger.warning("⚠ DEX 파일을 찾을 수 없습니다")
            else:
                # 각 DEX 파일 복호화 시도
                for dex_file in decryptor.dex_files:
                    result = decryptor.decrypt_dex_file(dex_file)
                    if result:
                        self.results['decrypted_files'].append(dex_file)
                
                if self.results['decrypted_files']:
                    self.logger.info(f"✓ {len(self.results['decrypted_files'])}개 DEX 파일 복호화 성공")
                else:
                    self.logger.warning("⚠ 복호화된 DEX 파일이 없습니다")
            
            # 4. APK 재패키징 및 서명
            self.logger.info("\n[4/4] APK 재패키징 및 서명 중...")
            packer = ApkPacker(str(extract_dir))
            
            # 복호화된 DEX 파일이 있으면 교체
            if self.results['decrypted_files']:
                decrypted_dir = extract_dir / 'decrypted_dex'
                if decrypted_dir.exists():
                    replaced = packer.replace_dex_files(str(decrypted_dir))
                    self.logger.info(f"  → {replaced}개 DEX 파일 교체됨")
            
            # 재패키징 및 서명 (pack 메서드가 자동으로 서명)
            repackaged_apk = packer.pack(exclude_dirs=['decrypted_dex'])
            self.results['repackaged_apk'] = str(repackaged_apk)
            self.logger.info(f"✓ APK 재패키징 완료: {repackaged_apk}")
            
            # 성공 플래그
            self.results['success'] = True
            
            # 최종 요약
            self.logger.info("\n" + "="*80)
            self.logger.info("파이프라인 실행 완료")
            self.logger.info("="*80)
            self.logger.info(f"원본 APK: {self.results['apk_path']}")
            self.logger.info(f"MobSF 리포트: {self.results['mobsf_report']}")
            self.logger.info(f"압축 해제: {self.results['extracted_dir']}")
            if self.results['decrypted_files']:
                self.logger.info(f"복호화된 DEX: {len(self.results['decrypted_files'])}개")
            if self.results['repackaged_apk']:
                self.logger.info(f"재패키징된 APK: {self.results['repackaged_apk']}")
            self.logger.info("="*80)
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"\n✗ 파이프라인 실행 중 오류 발생: {e}")
            self.results['error'] = str(e)
            return self.results


def main():
    """
    메인 함수 - CLI 인터페이스
    """
    parser = argparse.ArgumentParser(
        description="APK 정적 분석, DEX 복호화, 재패키징 통합 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예제:
  # 전체 파이프라인 실행
  python main.py sample.apk
  DEX 복호화 시
  # 테스트 모드 (MobSF 분석 건너뛰고 테스트 리포트 사용)
  python main.py sample.apk --test
  
  # API 키 직접 지정
  python main.py sample.apk --mobsf-api-key YOUR_API_KEY
  
  # MobSF 서버 URL 지정
  python main.py sample.apk --mobsf-url http://192.168.1.100:8000
        """
    )
    
    parser.add_argument('apk_path', help='APK 파일 경로')
    parser.add_argument('--test', action='store_true',
                       help='테스트 모드 (MobSF 분석 건너뛰고 static_analysis/output/mobsf_report_test.json 사용)')
    parser.add_argument('--mobsf-api-key', type=str,
                       help='MobSF API 키 (기본값: .env 파일에서 로드)')
    parser.add_argument('--mobsf-url', type=str,
                       help='MobSF 서버 URL (기본값: .env 파일에서 로드)')
    
    args = parser.parse_args()
    
    # 로깅 설정
    logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
    
    try:
        # 파이프라인 실행
        pipeline = StaticAnalysisPipeline(
            args.apk_path,
            mobsf_api_key=args.mobsf_api_key,
            mobsf_url=args.mobsf_url
        )
        
        results = pipeline.run_full_pipeline(test_mode=args.test)
        
        if results['success']:
            logger.info("\n✓ 모든 작업 성공!")
            sys.exit(0)
        else:
            logger.error("\n✗ 작업 실패")
            if 'error' in results:
                logger.error(f"오류: {results['error']}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"\n✗ 실행 중 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
