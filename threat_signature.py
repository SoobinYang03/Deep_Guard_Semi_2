malicious_behavior = {
    "계정 및 인증 정보 탈취": {
        "pattern": r"AccountManager\.(getAccounts|getAccountsByType|addOnAccountsUpdatedListener)|GoogleAuthUtil\.getToken|CookieManager\.getCookie|ContactsContract\.Profile",
        "desc": "기기에 등록된 구글,네이버,카카오 등 계정 정보 및 서비스 인증 토큰 무단 추출 시도"
    },
    "키로깅": {
        "pattern": r"EditText\.getText|addTextChangedListener|KeyEvent|dispatchKeyEvent|onKeyDown|TextWatcher",
        "desc": "사용자가 타이핑하는 내용을 실시간으로 훔치는 키로깅 시도"
    },
    "기기 식별 및 정보 수집": {
        "pattern": r"getDeviceId|getLine1Number|getSimSerialNumber|getSubscriberId|getImei|getMeid",
        "desc": "전화번호, IMEI 등 기기 고유 식별 정보를 수집하여 정밀한 사용자 추적 시도"
    },
    "연락처 및 사생활 유출": {
        "pattern": r"ContactsContract|READ_SMS|SMS_RECEIVED|Telephony\.Sms\.Intents|getAllMessages",
        "desc": "연락처 조회 및 문자 메시지 내용을 가로채 사생활 유출 시도"
    },
    "랜섬웨어": {
        "pattern": r"Cipher\.init.*ENCRYPT_MODE|javax\.crypto|SecretKeySpec|IvParameterSpec",
        "desc": "랜섬웨어에 감염시켜 금전을 요구하려는 시도"
    },
    "무작위 파괴": {
        "pattern": r"File\.delete|rm\s-rf|wipeData|formatFactory",
        "desc": "무작위 데이터를 파괴하여 기계를 못 쓰게 만들려는 시도"
    },
    "암호화폐 채굴": {
        "pattern": r"stratum\+tcp|cryptonight|minerd|cpuminer|xmrig",
        "desc": "기기 자원을 몰래 점유하여 암호화폐를 대신 채굴시키려는 시도"
    },
    "도청": {
        "pattern": r"AudioRecord|MediaRecorder\.AudioSource|AudioSource\.MIC|RECORD_AUDIO",
        "desc": "마이크를 활성화하여 주변 음성 및 통화 내용을 도청하려는 시도"
    },
    "DDoS 통로 활용": {
        "pattern": r"DatagramPacket|SocketChannel|flood|HTTP_POST.*attack|ping\s-f",
        "desc": "해당 기기를 봇넷으로 만들어 특정 서버에 DDoS 공격을 수행하는 통로로 사용하려는 시도"
    },
    "금융 정보 탈취": {
        "pattern": r"AccessibilityService|SYSTEM_ALERT_WINDOW|WindowManager\.LayoutParams\.TYPE_APPLICATION_OVERLAY",
        "desc": "접근성 권한, 화면 오버레이를 사용하여 은행 앱 위에 가짜 창을 띄워 정보를 탈취하려는 시도"
    },
    "시스템 상주": {
        "pattern": r"BOOT_COMPLETED|ACTION_REBOOT|ACTION_SHUTDOWN|QUICKBOOT_POWERON",
        "desc": "기기 재시작 시마다 자동으로 실행되어 분석 및 삭제를 회피하려는 시도"
    },
    "스파잉": {
        "pattern": r"ClipboardManager|getPrimaryClip|Browser\.SEARCH_HISTORY_BOOKMARKS|getHistory",
        "desc": "클립보드나 브라우저 방문 기록을 엿보면서 사생활을 침해하려는 시도"
    },
    "탐지 우회": {
        "pattern": r"isDebuggerConnected|frida-server|ptrace|checkSignature|isRooted|getProp.*ro\.debuggable",
        "desc": "디버깅 환경이나 Frida 등 우회 도구를 탐지하여 자신의 정체를 숨기려는 시도"
    },
    "결제 유도": {
        "pattern": r"billing\.client|PURCHASE_INTENT|IInAppBillingService|sendInAppBuyIntent",
        "desc": "동의 없이 인앱 결제를 실행하거나 서비스를 강제로 구독시키려는 시도"
    },
    "원격 조정": {
        "pattern": r"Socket\.connect|ServerSocket\.accept|HttpURLConnection|Runtime\.exec",
        "desc": "원격으로 기기 자체를 조작하려는 시도"
    }
}