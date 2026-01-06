console.log("[+] DeepGuard Frida Agent Loaded!");
function bypassJava() {
    Java.perform(function() {
        console.log("[*] Java runtime ready.");
        try {
            var Activity = Java.use("android.app.Activity");
            Activity.finish.overload().implementation = function() {
                console.log("[!] Activity.finish() 차단됨");
            };
        } catch(err) {
            console.log("[-] Java bypass error: " + err.message);
        }
    });
}

var dumpedAddresses = []; 

// 1초마다 반복
var intervalID = setInterval(function() {
    
    // 읽기/쓰기/실행 모든 권한 스캔
    ['r--', 'rw-', 'r-x'].forEach(function(perm) {
        Process.enumerateRanges(perm).forEach(function(range) {
            
            // 시스템 파일은 패스
            if (range.file && (range.file.path.startsWith("/system") || range.file.path.startsWith("/apex"))) {
                return; 
            }

            try {
                // "dex" 헤더 패턴 검색
                Memory.scan(range.base, range.size, "64 65 78 0a", {
                    onMatch: function(address, size) {
                        
                        // 이미 찾은 곳이면 패스
                        if (dumpedAddresses.indexOf(address.toString()) >= 0) return;

                        try {
                            // [핵심] 헤더를 먼저 읽어서 '진짜 파일 크기'를 알아냄
                            // DEX 헤더의 32번째 바이트부터 4바이트가 '파일 크기' 정보임
                            var fileSize = address.add(32).readU32();

                            // 크기가 너무 작거나(1KB 미만) 너무 크면(50MB 초과) 가짜로 판별 -> 무시
                            if (fileSize < 1000 || fileSize > 50000000) return;

                            console.log("[!] 진짜 DEX 발견! 주소: " + address + " 크기: " + fileSize + " bytes");
                            
                            // 정확한 크기만큼만 읽어서 전송 (에러 방지)
                            var buffer = address.readByteArray(fileSize);
                            
                            if (buffer) {
                                send({ 
                                    type: "dex_dump", 
                                    addr: address.toString(), 
                                    size: fileSize 
                                }, buffer);
                                
                                // 성공적으로 덤프했으면 목록에 추가
                                dumpedAddresses.push(address.toString());
                            }

        } catch(err) {
                            // 읽다가 에러 나면 가짜 파일임 -> 무시
                        }
                    },
                    onError: function(reason) {},
                    onComplete: function() {}
                });
            } catch (e) {}
        });
    });

}, 1000);

// 30초 뒤 종료
setTimeout(function() {
    console.log("[*] 주입 시작...");
    bypassJava();
    console.log("[*] 정밀 분석 종료.");
    clearInterval(intervalID);
}, 30000);