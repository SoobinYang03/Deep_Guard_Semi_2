"""
APK 재패키징 및 서명 유틸리티
압축 해제된 APK 파일들을 다시 패키징하고 서명
"""

import os
import zipfile
import shutil
import subprocess
from pathlib import Path
from typing import Optional
import logging

from logger_config import LoggerConfig


class ApkPacker:
    """
    압축 해제된 APK 파일들을 다시 패키징하고 서명하는 클래스
    """
    
    def __init__(self, extract_dir: str, output_dir: str = None):
        """
        초기화
        
        Args:
            extract_dir: 압축 해제된 APK 디렉토리 경로
            output_dir: 출력 디렉토리 (기본값: src/output/repackaged)
        """
        self.extract_dir = Path(extract_dir)
        
        if not self.extract_dir.exists():
            raise FileNotFoundError(f"압축 해제 디렉토리를 찾을 수 없습니다: {extract_dir}")
        
        # 출력 디렉토리 설정
        if output_dir is None:
            self.output_dir = Path(__file__).parent.parent / 'output' / 'decrypted'
        else:
            self.output_dir = Path(output_dir)
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 로깅 설정
        self.logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
    
    def pack(self, output_name: str = None, exclude_dirs: list = None, keystore_path: Optional[str] = None) -> Path:
        """
        APK 재패키징 및 자동 서명
        
        Args:
            output_name: 출력 APK 파일명 (기본값: 원본이름_repackaged.apk)
            exclude_dirs: 제외할 디렉토리 목록 (예: ['decrypted_dex'])
            keystore_path: 키스토어 파일 경로 (기본값: 디버그 키스토어)
        
        Returns:
            서명된 APK 파일 경로
        """
        self.logger.info("APK 재패키징 시작")
        
        # 출력 APK 파일명 설정
        if output_name is None:
            # extract_dir 이름에서 _extracted 제거
            base_name = self.extract_dir.name.replace('_extracted', '')
            output_name = f"{base_name}_repackaged.apk"
        
        output_apk = self.output_dir / output_name
        
        # 제외 디렉토리 설정
        if exclude_dirs is None:
            exclude_dirs = []
        
        try:
            with zipfile.ZipFile(output_apk, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # 모든 파일을 ZIP에 추가
                for root, dirs, files in os.walk(self.extract_dir):
                    # 제외 디렉토리 확인
                    should_skip = False
                    for exclude in exclude_dirs:
                        if exclude in root:
                            should_skip = True
                            break
                    
                    if should_skip:
                        continue
                    
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(self.extract_dir)
                        
                        zipf.write(file_path, arcname)
                        
            self.logger.info(f"APK 재패키징 완료: {output_apk}")
            
            # 자동 서명
            signed_apk = self.sign(output_apk, keystore_path)
            
            if signed_apk:
                # 서명 성공 시 서명된 APK 반환
                return signed_apk
            else:
                # 서명 실패 시 서명되지 않은 APK 반환
                self.logger.warning("서명 실패 - 서명되지 않은 APK 반환")
                return output_apk
            
        except Exception as e:
            self.logger.error(f"APK 재패키징 중 오류 발생: {e}")
            raise
    
    def sign(self, apk_path: Path, keystore_path: Optional[str] = None) -> Optional[Path]:
        """
        APK 서명 (apksigner 또는 jarsigner 사용)
        
        Args:
            apk_path: 서명할 APK 경로
            keystore_path: 키스토어 파일 경로 (선택사항)
        
        Returns:
            서명된 APK 경로 (실패 시 None)
        """
        self.logger.info("APK 서명 시작")
        
        # 서명된 APK 경로
        signed_apk = apk_path.parent.parent / f"decrypted" / f"{apk_path.stem}_signed.apk"
        
        # apksigner 사용 시도 (Android SDK Build Tools)
        try:
            # 기본 디버그 키스토어 사용
            if keystore_path is None:
                # Android 디버그 키스토어 경로
                debug_keystore = Path.home() / '.android' / 'debug.keystore'
                
                if not debug_keystore.exists():
                    self.logger.warning(f"디버그 키스토어를 찾을 수 없습니다: {debug_keystore}")
                    self.logger.info("apksigner로 직접 서명을 시도하세요")
                    return None
                
                keystore_path = str(debug_keystore)
            
            # apksigner 명령어 실행
            cmd = [
                'apksigner', 'sign',
                '--ks', keystore_path,
                '--ks-key-alias', 'androiddebugkey',
                '--ks-pass', 'pass:android',
                '--key-pass', 'pass:android',
                '--out', str(signed_apk),
                str(apk_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"APK 서명 완료: {signed_apk}")
                return signed_apk
            else:
                self.logger.error(f"apksigner 오류: {result.stderr}")
                
        except FileNotFoundError:
            self.logger.warning("apksigner를 찾을 수 없습니다 (Android SDK Build Tools 필요)")
        except Exception as e:
            self.logger.error(f"APK 서명 중 오류 발생: {e}")
        
        # jarsigner 사용 시도
        try:
            self.logger.info("jarsigner로 서명 시도")
            
            cmd = [
                'jarsigner',
                '-verbose',
                '-keystore', keystore_path,
                '-storepass', 'android',
                '-keypass', 'android',
                '-signedjar', str(signed_apk),
                str(apk_path),
                'androiddebugkey'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"APK 서명 완료 (jarsigner): {signed_apk}")
                return signed_apk
            else:
                self.logger.error(f"jarsigner 오류: {result.stderr}")
                
        except FileNotFoundError:
            self.logger.warning("jarsigner를 찾을 수 없습니다 (JDK 필요)")
        except Exception as e:
            self.logger.error(f"jarsigner 서명 중 오류 발생: {e}")
        
        self.logger.warning("APK 서명 실패 - apksigner 또는 jarsigner 설치 필요")
        return None
    
    def replace_dex_files(self, decrypted_dex_dir: str) -> int:
        """
        복호화된 DEX 파일로 원본 교체
        
        Args:
            decrypted_dex_dir: 복호화된 DEX 파일들이 있는 디렉토리
        
        Returns:
            교체된 DEX 파일 개수
        """
        decrypted_dir = Path(decrypted_dex_dir)
        
        if not decrypted_dir.exists():
            self.logger.warning(f"복호화 디렉토리를 찾을 수 없습니다: {decrypted_dir}")
            return 0
        
        # 복호화된 DEX 파일 목록
        decrypted_files = list(decrypted_dir.glob('*.dex'))
        
        if not decrypted_files:
            self.logger.warning("복호화된 DEX 파일이 없습니다")
            return 0
        
        replaced_count = 0
        
        for decrypted_file in decrypted_files:
            # decrypted_classes.dex -> classes.dex
            original_name = decrypted_file.name.replace('decrypted_', '')
            target_path = self.extract_dir / original_name
            
            self.logger.info(f"DEX 파일 교체: {original_name}")
            shutil.copy2(decrypted_file, target_path)
            replaced_count += 1
        
        self.logger.info(f"총 {replaced_count}개 DEX 파일 교체 완료")
        return replaced_count

def main():
    """
    메인 함수 - 사용 예제
    """
    import sys
    
    logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
    
    if len(sys.argv) < 2:
        logger.info("사용법: python apk_packer.py <압축해제디렉토리>")
        logger.info("예제: python apk_packer.py output/extracted/sample_extracted")
        sys.exit(1)
    
    extract_dir = sys.argv[1]
    
    try:
        packer = ApkPacker(extract_dir)
        
        # APK 재패키징 및 자동 서명
        output_apk = packer.pack(exclude_dirs=['decrypted_dex'])
        logger.info(f"✓ 재패키징 및 서명 완료: {output_apk}")
        
    except Exception as e:
        logger.error(f"실행 중 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
