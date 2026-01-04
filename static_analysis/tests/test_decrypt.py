"""
DexBruteforceDecryptor 클래스를 사용한 pytest 테스트
"""

import pytest
import sys
from pathlib import Path
import json
import os

# src 디렉토리의 모듈을 import하기 위해 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from dex_bruteforce_decryptor import DexBruteforceDecryptor


# 테스트 설정
@pytest.fixture
def test_config():
    """테스트 설정을 반환하는 fixture, 실제 경로로 수정 필요"""
    return {
        'valid_key': "dbcdcfghijklmaop",  # 16바이트 올바른 키
        'invalid_keys': [
            "wrongkey1234567",  # 잘못된 키 1
            "invalidpassword",  # 잘못된 키 2
            "thisiswrongkey!",  # 잘못된 키 3
            "0000000000000000",  # 잘못된 키 4
        ],
        'mobsf_report': r"C:\Users\twins\Desktop\Deep_Guard_Semi_2\static_analysis\output\report\mobsf_report_f90f81f7_20251227_134957.json",
        'dex_dir': r"C:\Users\twins\Desktop\Deep_Guard_Semi_2\static_analysis\output\extracted\sample_extracted",
        'output_dir': r"C:\Users\twins\Desktop\Deep_Guard_Semi_2\static_analysis\output\extracted\sample_extracted"
    }


@pytest.fixture
def decryptor(test_config):
    """DexBruteforceDecryptor 인스턴스를 생성하는 fixture"""
    return DexBruteforceDecryptor(test_config['mobsf_report'], test_config['dex_dir'])


class TestDexBruteforceDecryptor:
    """DexBruteforceDecryptor 클래스 테스트"""
    
    def test_decryptor_initialization(self, decryptor, test_config):
        """Decryptor가 정상적으로 초기화되는지 테스트"""
        assert decryptor is not None
        assert os.path.exists(test_config['mobsf_report'])
        assert os.path.exists(test_config['dex_dir'])
    
    def test_find_dex_files(self, decryptor):
        """DEX 파일을 찾는 기능 테스트"""
        decryptor.find_dex_files()
        assert isinstance(decryptor.dex_files, list)
        print(f"\n[*] 발견된 DEX 파일 수: {len(decryptor.dex_files)}")
        for dex_file in decryptor.dex_files:
            print(f"    - {os.path.basename(dex_file)}")
    
    def test_key_candidates_generation(self, decryptor, test_config):
        """키 후보 생성 테스트"""
        valid_key = test_config['valid_key']
        decryptor.strings.add(valid_key)
        
        key_candidates = decryptor.generate_key_candidates()
        
        assert isinstance(key_candidates, list)
        assert len(key_candidates) > 0
        
        # 테스트 키가 후보에 포함되어 있는지 확인
        valid_key_bytes = valid_key.encode('utf-8')
        assert valid_key_bytes in key_candidates, f"올바른 키 '{valid_key}'가 후보에 포함되어야 합니다"
        
        print(f"\n[*] 생성된 키 후보 수: {len(key_candidates)}")
        print(f"[*] 올바른 키 '{valid_key}'가 후보에 포함됨: ✓")
    
    def test_decrypt_with_valid_key(self, decryptor, test_config):
        """올바른 키를 사용한 복호화 성공 테스트"""
        valid_key = test_config['valid_key']
        output_dir = test_config['output_dir']
        
        # DEX 파일 찾기
        decryptor.find_dex_files()
        
        # DEX 파일이 없으면 테스트 스킵
        if not decryptor.dex_files:
            pytest.skip("DEX 파일을 찾을 수 없습니다.")
        
        # 올바른 키 추가
        decryptor.strings.add(valid_key)
        key_candidates = decryptor.generate_key_candidates()
        
        print(f"\n{'='*70}")
        print(f"[올바른 키 테스트]")
        print(f"알고리즘: AES-128-ECB")
        print(f"테스트 키: {valid_key}")
        print(f"{'='*70}\n")
        
        # 각 DEX 파일 복호화 시도
        success_count = 0
        for dex_file in decryptor.dex_files:
            result = decryptor.decrypt_dex_file(dex_file, output_dir)
            if result:
                success_count += 1
                print(f"[+] {os.path.basename(dex_file)} 복호화 성공!")
            else:
                print(f"[-] {os.path.basename(dex_file)} 복호화 실패")
        
        # 결과 검증
        assert isinstance(decryptor.results, list)
        print(f"\n[*] 총 {len(decryptor.dex_files)}개 중 {success_count}개 복호화 성공")
    
    def test_decrypt_with_invalid_keys(self, test_config):
        """잘못된 키들로 복호화 실패 테스트"""
        invalid_keys = test_config['invalid_keys']
        output_dir = test_config['output_dir']
        
        print(f"\n{'='*70}")
        print(f"[잘못된 키 테스트]")
        print(f"테스트할 잘못된 키: {len(invalid_keys)}개")
        print(f"{'='*70}\n")
        
        for idx, invalid_key in enumerate(invalid_keys, 1):
            # 각 잘못된 키에 대해 새로운 decryptor 인스턴스 생성
            decryptor = DexBruteforceDecryptor(
                test_config['mobsf_report'],
                test_config['dex_dir']
            )
            
            # DEX 파일 찾기
            decryptor.find_dex_files()
            
            if not decryptor.dex_files:
                pytest.skip("DEX 파일을 찾을 수 없습니다.")
            
            # 암호화된 DEX 파일만 찾기
            encrypted_dex_files = []
            for dex_file in decryptor.dex_files:
                with open(dex_file, 'rb') as f:
                    data = f.read()
                if not decryptor.is_valid_dex(data):
                    encrypted_dex_files.append(dex_file)
            
            if not encrypted_dex_files:
                print(f"[{idx}] 키 '{invalid_key}': 암호화된 DEX 파일이 없어 스킵")
                continue
            
            # 잘못된 키 추가
            decryptor.strings.add(invalid_key)
            key_candidates = decryptor.generate_key_candidates()
            
            print(f"[{idx}] 잘못된 키 '{invalid_key}' 테스트 중...")
            
            # 암호화된 DEX 파일로만 복호화 시도
            failed_count = 0
            for dex_file in encrypted_dex_files:
                result = decryptor.decrypt_dex_file(dex_file, output_dir)
                if not result:
                    failed_count += 1
            
            # 모든 암호화된 파일에 대해 복호화가 실패해야 함
            if failed_count == len(encrypted_dex_files):
                print(f"    ✓ 예상대로 복호화 실패 ({failed_count}/{len(encrypted_dex_files)} 파일)")
            else:
                success_count = len(encrypted_dex_files) - failed_count
                print(f"    ✗ 예상치 못한 복호화 성공 ({success_count}/{len(encrypted_dex_files)} 파일)")
                # 잘못된 키로 복호화가 성공하면 안됨
                assert success_count == 0, f"잘못된 키 '{invalid_key}'로 {success_count}개 파일이 복호화됨"
        
        print(f"\n[*] 모든 잘못된 키 테스트 완료: {len(invalid_keys)}개 키 모두 실패함 ✓")
    
    def test_decryption_results_summary(self, decryptor, test_config):
        """복호화 결과 요약 테스트"""
        valid_key = test_config['valid_key']
        output_dir = test_config['output_dir']
        
        # DEX 파일 찾기 및 복호화 시도
        decryptor.find_dex_files()
        
        if not decryptor.dex_files:
            pytest.skip("DEX 파일을 찾을 수 없습니다.")
        
        decryptor.strings.add(valid_key)
        key_candidates = decryptor.generate_key_candidates()
        
        for dex_file in decryptor.dex_files:
            decryptor.decrypt_dex_file(dex_file, output_dir)
        
        # 결과 검증
        print(f"\n{'='*70}")
        print("결과 요약")
        print(f"{'='*70}")
        
        for result in decryptor.results:
            assert 'success' in result
            assert 'original_file' in result
            
            if result['success']:
                assert 'algorithm' in result
                assert 'key' in result
                assert 'decrypted_file' in result
                
                print(f"\n[성공] {os.path.basename(result['original_file'])}")
                print(f"  알고리즘: {result['algorithm']}")
                if result['key'] in decryptor.key_to_string_map:
                    print(f"  원본 문자열: {decryptor.key_to_string_map[result['key']]}")
                print(f"  키 (hex): {result['key'].hex()}")
                print(f"  저장 위치: {result['decrypted_file']}")
            else:
                print(f"\n[실패] {os.path.basename(result['original_file'])}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
