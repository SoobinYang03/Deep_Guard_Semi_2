"""
APK 압축 해제 유틸리티
APK 파일을 ZIP 포맷으로 압축 해제
"""

import zipfile
import shutil
from pathlib import Path
import logging

from logger_config import LoggerConfig


class ApkExtractor:
    """
    APK 파일을 압축 해제하는 클래스
    """
    
    def __init__(self, apk_path: str, output_dir: str = None):
        """
        초기화
        
        Args:
            apk_path: 원본 APK 파일 경로
            output_dir: 압축 해제 디렉토리 (기본값: src/output/extracted)
        """
        self.apk_path = Path(apk_path)
        
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK 파일을 찾을 수 없습니다: {apk_path}")
        
        # 출력 디렉토리 설정
        if output_dir is None:
            self.output_dir = Path(__file__).parent.parent / 'output' / 'extracted'
        else:
            self.output_dir = Path(output_dir)
        
        # 압축 해제 디렉토리 경로
        self.extract_dir = self.output_dir / f"{self.apk_path.stem}_extracted"
        
        # 로깅 설정
        self.logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
    
    def extract(self, force: bool = False) -> Path:
        """
        APK 파일 압축 해제
        
        Args:
            force: True면 기존 디렉토리 삭제 후 재압축 해제
        
        Returns:
            압축 해제된 디렉토리 경로
        """
        self.logger.info(f"APK 압축 해제 시작: {self.apk_path}")
        
        # 기존 디렉토리 처리
        if self.extract_dir.exists():
            if force:
                self.logger.warning(f"기존 디렉토리 삭제: {self.extract_dir}")
                shutil.rmtree(self.extract_dir)
            else:
                self.logger.info(f"이미 압축 해제된 디렉토리가 존재합니다: {self.extract_dir}")
                return self.extract_dir
        
        # 디렉토리 생성
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        
        # APK 압축 해제 (APK는 ZIP 포맷)
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(self.extract_dir)
            
            self.logger.info(f"APK 압축 해제 완료: {self.extract_dir}")
            
            # 추출된 파일 목록 출력
            extracted_files = list(self.extract_dir.rglob('*'))
            self.logger.info(f"총 {len(extracted_files)}개 파일 추출됨")
            
            # DEX 파일 목록 출력
            dex_files = list(self.extract_dir.glob('*.dex'))
            if dex_files:
                self.logger.info(f"발견된 DEX 파일: {[f.name for f in dex_files]}")
            else:
                self.logger.warning("DEX 파일을 찾을 수 없습니다")
            
            return self.extract_dir
            
        except zipfile.BadZipFile:
            self.logger.error(f"잘못된 ZIP/APK 파일입니다: {self.apk_path}")
            raise
        except Exception as e:
            self.logger.error(f"APK 압축 해제 중 오류 발생: {e}")
            raise
    
    def get_dex_files(self) -> list:
        """
        압축 해제된 디렉토리에서 DEX 파일 목록 반환
        
        Returns:
            DEX 파일 경로 리스트
        """
        if not self.extract_dir.exists():
            raise FileNotFoundError(f"압축 해제 디렉토리를 찾을 수 없습니다: {self.extract_dir}")
        
        dex_files = list(self.extract_dir.glob('*.dex'))
        return [str(f) for f in dex_files]
    
    def get_manifest(self) -> Path:
        """
        AndroidManifest.xml 파일 경로 반환
        
        Returns:
            AndroidManifest.xml 경로
        """
        if not self.extract_dir.exists():
            raise FileNotFoundError(f"압축 해제 디렉토리를 찾을 수 없습니다: {self.extract_dir}")
        
        manifest = self.extract_dir / 'AndroidManifest.xml'
        if not manifest.exists():
            raise FileNotFoundError("AndroidManifest.xml을 찾을 수 없습니다")
        
        return manifest


def main():
    """
    메인 함수 - 사용 예제
    """
    import sys
    
    logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
    
    if len(sys.argv) < 2:
        logger.info("사용법: python apk_extractor.py <APK파일경로>")
        logger.info("예제: python apk_extractor.py sample.apk")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    
    try:
        extractor = ApkExtractor(apk_path)
        extract_dir = extractor.extract(force=True)
        
        logger.info(f"✓ 압축 해제 완료: {extract_dir}")
        
        # DEX 파일 목록 출력
        dex_files = extractor.get_dex_files()
        if dex_files:
            logger.info(f"  DEX 파일: {dex_files}")
        
    except Exception as e:
        logger.error(f"실행 중 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
