"""
로깅 설정 유틸리티
프로젝트 전체에서 일관된 로깅 형식을 제공
"""

import logging
import sys
from typing import Optional


class LoggerConfig:
    """로거 설정 및 관리 클래스"""
    
    _loggers = {}  # 생성된 로거들을 캐싱
    
    @staticmethod
    def get_logger(
        name: str,
        level: int = logging.INFO,
        log_format: Optional[str] = None,
        date_format: Optional[str] = None
    ) -> logging.Logger:
        """
        설정된 로거 인스턴스 반환
        
        Args:
            name: 로거 이름 (일반적으로 __name__ 사용)
            level: 로그 레벨 (기본값: logging.INFO)
            log_format: 로그 포맷 (기본값: None - 기본 포맷 사용)
            date_format: 날짜 포맷 (기본값: None - 기본 포맷 사용)
            
        Returns:
            설정된 Logger 인스턴스
        """
        # 이미 생성된 로거가 있으면 반환
        if name in LoggerConfig._loggers:
            return LoggerConfig._loggers[name]
        
        # 새 로거 생성
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # 기존 핸들러가 있으면 제거 (중복 방지)
        if logger.handlers:
            logger.handlers.clear()
        
        # 콘솔 핸들러 추가
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        # 포맷 설정
        if log_format is None:
            log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        if date_format is None:
            date_format = '%Y-%m-%d %H:%M:%S'
        
        formatter = logging.Formatter(log_format, datefmt=date_format)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        
        # 상위 로거로 전파 방지 (중복 로그 방지)
        logger.propagate = False
        
        # 캐싱
        LoggerConfig._loggers[name] = logger
        
        return logger
    
    @staticmethod
    def get_simple_logger(name: str, level: int = logging.INFO) -> logging.Logger:
        """
        간단한 포맷의 로거 반환 (모듈 이름 없음)
        
        Args:
            name: 로거 이름
            level: 로그 레벨
            
        Returns:
            설정된 Logger 인스턴스
        """
        return LoggerConfig.get_logger(
            name=name,
            level=level,
            log_format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    @staticmethod
    def set_level(logger_name: str, level: int):
        """
        특정 로거의 레벨 변경
        
        Args:
            logger_name: 로거 이름
            level: 새로운 로그 레벨
        """
        if logger_name in LoggerConfig._loggers:
            logger = LoggerConfig._loggers[logger_name]
            logger.setLevel(level)
            for handler in logger.handlers:
                handler.setLevel(level)
