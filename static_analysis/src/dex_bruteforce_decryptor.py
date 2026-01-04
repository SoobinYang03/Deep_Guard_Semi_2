"""
DEX 파일 브루트포스 복호화 클래스
MobSF 리포트의 문자열을 이용하여 암호화된 DEX 파일을 복호화 시도
"""

import json
import os
import hashlib
import logging
from typing import List, Set, Optional, Tuple
import itertools
from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4
from Crypto.Util.Padding import unpad
import struct

from logger_config import LoggerConfig


class DexBruteforceDecryptor:
    """
    MobSF 분석 리포트의 문자열을 이용하여 DEX 파일을 브루트포스 복호화하는 클래스
    """
    
    def __init__(self, mobsf_report_path: str, dex_directory: str):
        """
        초기화
        
        Args:
            mobsf_report_path: MobSF JSON 리포트 파일 경로
            dex_directory: DEX 파일들이 있는 디렉토리 경로
        """
        self.mobsf_report_path = mobsf_report_path
        self.dex_directory = dex_directory
        self.strings: Set[str] = set()
        self.dex_files: List[str] = []
        self.results = []
        self.key_to_string_map = {}  # 키 -> 원본 문자열 매핑
        
        # 로깅 설정
        self.logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
        
    def load_strings_from_report(self) -> Set[str]:
        """
        MobSF 리포트에서 모든 문자열 추출
        
        Returns:
            추출된 문자열 집합
        """
        self.logger.info(f"MobSF 리포트 로딩: {self.mobsf_report_path}")
        
        try:
            with open(self.mobsf_report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # strings_apk_res에서 문자열 추출
            if 'strings' in report_data and 'strings_apk_res' in report_data['strings']:
                for string_entry in report_data['strings']['strings_apk_res']:
                    # "key" : "value" 형식에서 value 추출
                    if ':' in string_entry:
                        parts = string_entry.split(':', 1)
                        if len(parts) == 2:
                            value = parts[1].strip().strip('"')
                            if value and len(value) > 0:
                                self.strings.add(value)
            
            # strings_so에서 문자열 추출
            if 'strings' in report_data and 'strings_so' in report_data['strings']:
                for lib_entry in report_data['strings']['strings_so']:
                    for lib_name, string_list in lib_entry.items():
                        for string_val in string_list:
                            if string_val and len(string_val) > 0:
                                self.strings.add(string_val)
            
            # strings_code에서 문자열 추출
            if 'strings' in report_data and 'strings_code' in report_data['strings']:
                for string_val in report_data['strings']['strings_code']:
                    if string_val and len(string_val) > 0:
                        self.strings.add(string_val)
            
            # 기타 메타데이터에서 유용한 문자열 추출
            useful_keys = [
                'package_name', 'app_name', 'version_name', 'version_code',
                'md5', 'sha1', 'sha256', 'file_name'
            ]
            for key in useful_keys:
                if key in report_data and report_data[key]:
                    self.strings.add(str(report_data[key]))
            
            # Activities, Services, Receivers에서 문자열 추출
            for component_type in ['activities', 'services', 'receivers', 'providers']:
                if component_type in report_data:
                    for component in report_data[component_type]:
                        self.strings.add(component)
            
            self.logger.info(f"총 {len(self.strings)}개의 고유 문자열 추출 완료")
            return self.strings
            
        except Exception as e:
            self.logger.error(f"리포트 로딩 실패: {e}")
            raise
    
    def find_dex_files(self) -> List[str]:
        """
        지정된 디렉토리에서 DEX 파일 찾기
        
        Returns:
            DEX 파일 경로 리스트
        """
        self.logger.info(f"DEX 파일 검색: {self.dex_directory}")
        
        self.dex_files = []
        
        # .dex 파일 찾기
        for root, dirs, files in os.walk(self.dex_directory):
            for file in files:
                if file.endswith('.dex'):
                    full_path = os.path.join(root, file)
                    self.dex_files.append(full_path)
        
        self.logger.info(f"{len(self.dex_files)}개의 DEX 파일 발견: {[os.path.basename(f) for f in self.dex_files]}")
        return self.dex_files
    
    def generate_key_candidates(self) -> List[bytes]:
        """
        문자열을 기반으로 암호화 키 후보 생성
        
        Returns:
            암호화 키 후보 리스트
        """
        self.logger.info("암호화 키 후보 생성 중...")
        
        key_candidates = []
        seen_hashes = set()  # 중복 제거를 위한 해시 집합
        
        # 직접 문자열을 키로 사용
        for s in self.strings:
            # 중복 확인을 위해 해시 계산
            key_hash = hashlib.md5(s.encode('utf-8')).hexdigest()
            
            if key_hash not in seen_hashes:
                seen_hashes.add(key_hash)
                
                # UTF-8 인코딩
                utf8_key = s.encode('utf-8')
                key_candidates.append(utf8_key)
                self.key_to_string_map[utf8_key] = f"{s} (UTF-8)"
                
                # ASCII 인코딩 시도 (UTF-8과 다른 경우에만)
                try:
                    ascii_encoded = s.encode('ascii')
                    if ascii_encoded != s.encode('utf-8'):
                        key_candidates.append(ascii_encoded)
                        self.key_to_string_map[ascii_encoded] = f"{s} (ASCII)"
                except:
                    pass
        
        self.logger.info(f"{len(key_candidates)}개의 키 후보 생성 완료 (중복 제거됨)")
        return key_candidates
    
    def try_xor_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        XOR 복호화 시도
        
        Args:
            encrypted_data: 암호화된 데이터
            key: 복호화 키
            
        Returns:
            복호화된 데이터
        """
        if not key:
            return encrypted_data
        
        decrypted = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(encrypted_data):
            decrypted.append(byte ^ key[i % key_len])
        
        return bytes(decrypted)
    
    def try_aes_decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes = None) -> List[Tuple[bytes, str]]:
        """
        AES 복호화 시도 (여러 모드)
        
        Args:
            encrypted_data: 암호화된 데이터
            key: 복호화 키
            iv: 초기화 벡터 (선택적)
            
        Returns:
            (복호화된 데이터, 모드명) 튜플 리스트
        """
        results = []
        
        # 키 길이 조정 (16, 24, 32 바이트)
        for key_size in [16, 24, 32]:
            try:
                adjusted_key = self._adjust_key_size(key, key_size)
                
                # ECB 모드 (IV 불필요)
                try:
                    cipher = AES.new(adjusted_key, AES.MODE_ECB)
                    decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 16)])
                    try:
                        decrypted = unpad(decrypted, AES.block_size)
                    except:
                        pass
                    results.append((decrypted, f'AES-{key_size*8}-ECB'))
                except:
                    pass
                
                # CBC, CTR, CFB, OFB 모드 (IV 필요)
                if iv is None:
                    iv = b'\x00' * 16  # 기본 IV
                else:
                    iv = self._adjust_key_size(iv, 16)
                
                # CBC 모드
                try:
                    cipher = AES.new(adjusted_key, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 16)])
                    try:
                        decrypted = unpad(decrypted, AES.block_size)
                    except:
                        pass
                    results.append((decrypted, f'AES-{key_size*8}-CBC'))
                except:
                    pass
                
                # CTR 모드
                try:
                    cipher = AES.new(adjusted_key, AES.MODE_CTR, nonce=iv[:8])
                    decrypted = cipher.decrypt(encrypted_data)
                    results.append((decrypted, f'AES-{key_size*8}-CTR'))
                except:
                    pass
                
                # CFB 모드
                try:
                    cipher = AES.new(adjusted_key, AES.MODE_CFB, iv)
                    decrypted = cipher.decrypt(encrypted_data)
                    results.append((decrypted, f'AES-{key_size*8}-CFB'))
                except:
                    pass
                
            except:
                pass
        
        return results
    
    def try_des_decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes = None) -> List[Tuple[bytes, str]]:
        """
        DES 복호화 시도
        
        Args:
            encrypted_data: 암호화된 데이터
            key: 복호화 키
            iv: 초기화 벡터 (선택적)
            
        Returns:
            (복호화된 데이터, 모드명) 튜플 리스트
        """
        results = []
        
        try:
            adjusted_key = self._adjust_key_size(key, 8)  # DES는 8바이트 키
            
            # ECB 모드
            try:
                cipher = DES.new(adjusted_key, DES.MODE_ECB)
                decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 8)])
                try:
                    decrypted = unpad(decrypted, DES.block_size)
                except:
                    pass
                results.append((decrypted, 'DES-ECB'))
            except:
                pass
            
            # CBC 모드
            if iv is None:
                iv = b'\x00' * 8
            else:
                iv = self._adjust_key_size(iv, 8)
            
            try:
                cipher = DES.new(adjusted_key, DES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 8)])
                try:
                    decrypted = unpad(decrypted, DES.block_size)
                except:
                    pass
                results.append((decrypted, 'DES-CBC'))
            except:
                pass
            
        except:
            pass
        
        return results
    
    def try_3des_decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes = None) -> List[Tuple[bytes, str]]:
        """
        3DES 복호화 시도
        
        Args:
            encrypted_data: 암호화된 데이터
            key: 복호화 키
            iv: 초기화 벡터 (선택적)
            
        Returns:
            (복호화된 데이터, 모드명) 튜플 리스트
        """
        results = []
        
        try:
            # 3DES는 16 또는 24 바이트 키
            for key_size in [16, 24]:
                try:
                    adjusted_key = self._adjust_key_size(key, key_size)
                    
                    # ECB 모드
                    try:
                        cipher = DES3.new(adjusted_key, DES3.MODE_ECB)
                        decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 8)])
                        try:
                            decrypted = unpad(decrypted, DES3.block_size)
                        except:
                            pass
                        results.append((decrypted, f'3DES-{key_size*8}-ECB'))
                    except:
                        pass
                    
                    # CBC 모드
                    if iv is None:
                        iv = b'\x00' * 8
                    else:
                        iv = self._adjust_key_size(iv, 8)
                    
                    try:
                        cipher = DES3.new(adjusted_key, DES3.MODE_CBC, iv)
                        decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 8)])
                        try:
                            decrypted = unpad(decrypted, DES3.block_size)
                        except:
                            pass
                        results.append((decrypted, f'3DES-{key_size*8}-CBC'))
                    except:
                        pass
                    
                except:
                    pass
        except:
            pass
        
        return results
    
    def try_blowfish_decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes = None) -> List[Tuple[bytes, str]]:
        """
        Blowfish 복호화 시도
        
        Args:
            encrypted_data: 암호화된 데이터
            key: 복호화 키
            iv: 초기화 벡터 (선택적)
            
        Returns:
            (복호화된 데이터, 모드명) 튜플 리스트
        """
        results = []
        
        try:
            # Blowfish는 4-56 바이트 키 (일반적으로 16바이트 사용)
            for key_size in [16, 32]:
                try:
                    adjusted_key = self._adjust_key_size(key, key_size)
                    
                    # ECB 모드
                    try:
                        cipher = Blowfish.new(adjusted_key, Blowfish.MODE_ECB)
                        decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 8)])
                        try:
                            decrypted = unpad(decrypted, Blowfish.block_size)
                        except:
                            pass
                        results.append((decrypted, f'Blowfish-{key_size*8}-ECB'))
                    except:
                        pass
                    
                    # CBC 모드
                    if iv is None:
                        iv = b'\x00' * 8
                    else:
                        iv = self._adjust_key_size(iv, 8)
                    
                    try:
                        cipher = Blowfish.new(adjusted_key, Blowfish.MODE_CBC, iv)
                        decrypted = cipher.decrypt(encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 8)])
                        try:
                            decrypted = unpad(decrypted, Blowfish.block_size)
                        except:
                            pass
                        results.append((decrypted, f'Blowfish-{key_size*8}-CBC'))
                    except:
                        pass
                    
                except:
                    pass
        except:
            pass
        
        return results
    
    def try_rc4_decrypt(self, encrypted_data: bytes, key: bytes) -> List[Tuple[bytes, str]]:
        """
        RC4 복호화 시도
        
        Args:
            encrypted_data: 암호화된 데이터
            key: 복호화 키
            
        Returns:
            (복호화된 데이터, 모드명) 튜플 리스트
        """
        results = []
        
        try:
            for key_size in [16, 32]:
                try:
                    adjusted_key = self._adjust_key_size(key, key_size)
                    cipher = ARC4.new(adjusted_key)
                    decrypted = cipher.decrypt(encrypted_data)
                    results.append((decrypted, f'RC4-{key_size*8}'))
                except:
                    pass
        except:
            pass
        
        return results
    
    def _adjust_key_size(self, key: bytes, target_size: int) -> bytes:
        """
        키를 목표 크기로 조정
        
        Args:
            key: 원본 키
            target_size: 목표 크기 (바이트)
            
        Returns:
            조정된 키
        """
        if len(key) == target_size:
            return key
        elif len(key) > target_size:
            return key[:target_size]
        else:
            # 반복하여 목표 크기 채우기
            return (key * ((target_size // len(key)) + 1))[:target_size]
    
    def is_valid_dex(self, data: bytes) -> bool:
        """
        유효한 DEX 파일인지 확인
        
        Args:
            data: 검증할 데이터
            
        Returns:
            유효한 DEX 파일이면 True
        """
        # DEX 파일 매직 넘버 확인
        # Standard DEX: dex\n035\0 또는 dex\n036\0 등
        if len(data) < 8:
            return False
        
        # DEX 매직 넘버 확인
        if data[:3] == b'dex':
            # dex\n 확인
            if data[3] == 0x0a:
                # 버전 확인 (035, 036, 037, 038, 039 등)
                version = data[4:7]
                try:
                    version_str = version.decode('ascii')
                    if version_str.isdigit() and data[7] == 0x00:
                        return True
                except:
                    pass
        
        return False
    
    def decrypt_dex_file(self, dex_path: str, output_dir: Optional[str] = None) -> str:
        """
        DEX 파일 복호화 시도
        
        Args:
            dex_path: DEX 파일 경로
            output_dir: 복호화된 파일 저장 디렉토리 (None이면 원본 디렉토리)
            
        Returns:
            "success": 복호화 성공
            "already_valid": 이미 유효한 DEX 파일
            "failed": 복호화 실패
        """
        self.logger.info(f"DEX 파일 복호화 시도: {os.path.basename(dex_path)}")
        
        try:
            with open(dex_path, 'rb') as f:
                encrypted_data = f.read()
            
            # 이미 유효한 DEX 파일인지 확인
            if self.is_valid_dex(encrypted_data):
                self.logger.warning(f"{os.path.basename(dex_path)}는 이미 유효한 DEX 파일입니다.")
                return "already_valid"
            
            # 키 후보 생성
            key_candidates = self.generate_key_candidates()
            
            self.logger.info(f"{len(key_candidates)}개의 키로 브루트포스 시도 중...")
            self.logger.info("시도할 알고리즘: XOR, AES, DES, 3DES, Blowfish, RC4")
            self.logger.info(f"예상 총 시도 횟수: 약 {len(key_candidates) * 90:,}회")
            
            # 각 키로 복호화 시도
            for idx, key in enumerate(key_candidates):
                progress = (idx + 1) / len(key_candidates) * 100
                
                # 현재 키 정보 출력
                key_info = self.key_to_string_map.get(key, key.hex()[:50])
                self.logger.debug(f"[{idx+1}/{len(key_candidates)}] ({progress:.1f}%) | 키: {key_info[:40]}...")
                
                # IV 후보 (키의 일부, 0으로 채워진 값 등)
                iv_candidates = [None, key, b'\x00' * 16, encrypted_data[:16]]
                
                decrypt_methods = []
                
                # 1. XOR 복호화
                decrypt_methods.append(('XOR', [(self.try_xor_decrypt(encrypted_data, key), 'XOR')]))
                
                # 2. AES 복호화 (여러 IV로 시도)
                for iv in iv_candidates:
                    decrypt_methods.append(('AES', self.try_aes_decrypt(encrypted_data, key, iv)))
                
                # 3. DES 복호화
                for iv in iv_candidates:
                    decrypt_methods.append(('DES', self.try_des_decrypt(encrypted_data, key, iv)))
                
                # 4. 3DES 복호화
                for iv in iv_candidates:
                    decrypt_methods.append(('3DES', self.try_3des_decrypt(encrypted_data, key, iv)))
                
                # 5. Blowfish 복호화
                for iv in iv_candidates:
                    decrypt_methods.append(('Blowfish', self.try_blowfish_decrypt(encrypted_data, key, iv)))
                
                # 6. RC4 복호화
                decrypt_methods.append(('RC4', self.try_rc4_decrypt(encrypted_data, key)))
                
                # 모든 복호화 결과 확인
                for method_name, results in decrypt_methods:
                    for decrypted_data, mode_name in results:
                        if decrypted_data and self.is_valid_dex(decrypted_data):
                            self.logger.info("복호화 성공!")
                            self.logger.info(f"알고리즘: {mode_name}")
                            
                            # 원본 문자열 출력
                            if key in self.key_to_string_map:
                                self.logger.info(f"원본 문자열: {self.key_to_string_map[key]}")
                            
                            # 키 hex 출력
                            if len(key) <= 64:
                                self.logger.info(f"키 (hex): {key.hex()}")
                            else:
                                self.logger.info(f"키 (hex): {key[:32].hex()}... (길이: {len(key)} bytes)")
                            
                            # 복호화된 파일 저장
                            if output_dir is None:
                                output_dir = os.path.dirname(dex_path)
                            
                            base_name = os.path.basename(dex_path)
                            output_path = os.path.join(output_dir, base_name)
                            
                            with open(output_path, 'wb') as f:
                                f.write(decrypted_data)
                            
                            self.logger.info(f"저장 위치: {output_path}")
                            
                            self.results.append({
                                'original_file': dex_path,
                                'decrypted_file': output_path,
                                'key': key,
                                'algorithm': mode_name,
                                'success': True
                            })
                            
                            return "success"
            
            self.logger.warning("복호화 실패: 유효한 키를 찾지 못했습니다.")
            self.results.append({
                'original_file': dex_path,
                'decrypted_file': None,
                'key': None,
                'success': False
            })
            return "failed"
            
        except Exception as e:
            self.logger.error(f"오류 발생: {e}")
            return "failed"
    
    def run(self, output_dir: Optional[str] = None) -> dict:
        """
        전체 복호화 프로세스 실행
        
        Args:
            output_dir: 복호화된 파일 저장 디렉토리
            
        Returns:
            결과 딕셔너리
        """
        self.logger.info("="*70)
        self.logger.info("DEX 파일 브루트포스 복호화 시작")
        self.logger.info("="*70)
        
        # 1. 문자열 추출
        self.load_strings_from_report()
        
        # 2. DEX 파일 찾기
        self.find_dex_files()
        
        if not self.dex_files:
            self.logger.error("DEX 파일을 찾을 수 없습니다.")
            return {'success': False, 'message': 'No DEX files found'}
        
        # 3. 각 DEX 파일 복호화 시도
        for dex_file in self.dex_files:
            self.decrypt_dex_file(dex_file, output_dir)
        
        # 4. 결과 요약
        self.logger.info("\n" + "="*70)
        self.logger.info("복호화 결과 요약")
        self.logger.info("="*70)
        
        success_count = sum(1 for r in self.results if r['success'])
        total_count = len(self.results)
        
        self.logger.info(f"총 DEX 파일: {total_count}")
        self.logger.info(f"복호화 성공: {success_count}")
        self.logger.info(f"복호화 실패: {total_count - success_count}")
        
        if success_count > 0:
            self.logger.info("성공한 파일:")
            for result in self.results:
                if result['success']:
                    self.logger.info(f"  - {os.path.basename(result['original_file'])} -> {result['decrypted_file']}")
        
        return {
            'success': success_count > 0,
            'total': total_count,
            'success_count': success_count,
            'results': self.results
        }


if __name__ == "__main__":
    import sys
    
    # 로깅 설정
    logger = LoggerConfig.get_simple_logger(__name__, level=logging.INFO)
    
    # 사용법 안내
    if len(sys.argv) < 3:
        logger.info("사용법: python dex_bruteforce_decryptor.py <MobSF리포트경로> <DEX디렉토리>")
        logger.info("예제: python dex_bruteforce_decryptor.py output/report/mobsf_report.json output/extracted/sample_extracted")
        sys.exit(1)
    
    mobsf_report = sys.argv[1]
    dex_dir = sys.argv[2]
    
    # 경로 유효성 검사
    if not os.path.exists(mobsf_report):
        logger.error(f"MobSF 리포트 파일을 찾을 수 없습니다: {mobsf_report}")
        sys.exit(1)
    
    if not os.path.exists(dex_dir):
        logger.error(f"DEX 디렉토리를 찾을 수 없습니다: {dex_dir}")
        sys.exit(1)
    
    # 복호화 실행
    try:
        decryptor = DexBruteforceDecryptor(mobsf_report, dex_dir)
        results = decryptor.run()
        
        logger.info("프로세스 완료!")
        
        if results['success']:
            logger.info(f"✓ {results['success_count']}개 파일 복호화 성공")
        else:
            logger.warning("✗ 복호화 실패")
            
    except Exception as e:
        logger.error(f"실행 중 오류 발생: {e}")
        sys.exit(1)
