console.log("[+] DeepGuard Bypass Script Loaded!");

// Java 런타임이 준비될 때까지 대기
function waitForJava() {
    if (typeof Java !== 'undefined') {
        console.log("[*] Java 런타임 발견, bypass 시작...");
        bypassJava();
    } else {
        console.log("[*] Java 런타임 대기 중...");
        setTimeout(waitForJava, 1000);
    }
}

function bypassJava() {
    Java.perform(function() {
        console.log("[*] Java runtime ready.");
        try {
            var Activity = Java.use("android.app.Activity");
            Activity.finish.overload().implementation = function() {
                console.log("[!] Activity.finish() 차단됨");
            };
            console.log("[+] Activity.finish() 후킹 완료");
        } catch(err) {
            console.log("[-] Java bypass error: " + err.message);
        }
    });
}

// 초기 대기 후 시작
setTimeout(waitForJava, 2000);
