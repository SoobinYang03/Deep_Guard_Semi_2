{
  "generated_at": "2026-01-05T09:31:33.756038Z",
  "inputs": {
    "out_dir": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a",
    "evidence_path": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/evidence.json",
    "jadx_dir": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/jadx",
    "apktool_dir": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/apktool",
    "dumpsys_package_path": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/runtime/dumpsys_package.txt"
  },
  "executive_summary": "",
  "behavior_classification": {},
  "evasion_detection": {},
  "ioc": {
    "artifacts": {
      "urls": [],
      "domains": [],
      "ips": [],
      "emails": []
    }
  },
  "findings": [],
  "mitre": {
    "techniques": [
      {
        "technique_id": "T1412",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.ABUSE.SMS_SEND"
      },
      {
        "technique_id": "T1638",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.ACCESSIBILITY.SERVICE"
      },
      {
        "technique_id": "T1622",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.ANTI.ANALYSIS.FRIDA"
      },
      {
        "technique_id": "T1406",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.CRYPTO.AES_ECB"
      },
      {
        "technique_id": "T1407",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.DYNLOAD.DEXCLASSLOADER"
      },
      {
        "technique_id": "T1437",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.NET.C2_STRINGS"
      },
      {
        "technique_id": "T1628",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.OVERLAY.SYSTEM_ALERT_WINDOW"
      },
      {
        "technique_id": "T1430",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.ABUSE.CALL_LOG"
      },
      {
        "technique_id": "T1636",
        "technique": "",
        "weight": 1,
        "reason": "from tag DG.NET.CERT_PINNING_HINT"
      }
    ],
    "notes": []
  },
  "badges": [
    {
      "type": "overall_risk",
      "label": "Overall Risk",
      "severity": "high",
      "reason": "Unified tags: 20 tags (max_severity=high)",
      "source": "unified_tags"
    }
  ],
  "tags": [
    {
      "id": "DG.ABUSE.SMS_SEND",
      "severity": "high",
      "reason": "SMS sending APIs hinted (hits=3)",
      "source": "decryption",
      "evidence": {
        "hits": 3
      },
      "mitre": [
        "T1412"
      ]
    },
    {
      "id": "DG.ACCESSIBILITY.SERVICE",
      "severity": "high",
      "reason": "AccessibilityService usage indicators (potential abuse) (hits=19)",
      "source": "decryption",
      "evidence": {
        "hits": 19
      },
      "mitre": [
        "T1638"
      ]
    },
    {
      "id": "DG.ANTI.ANALYSIS.FRIDA",
      "severity": "high",
      "reason": "Frida detection keywords (frida-server/gadget) (hits=2)",
      "source": "decryption",
      "evidence": {
        "hits": 2
      },
      "mitre": [
        "T1622"
      ]
    },
    {
      "id": "DG.CRYPTO.AES_ECB",
      "severity": "high",
      "reason": "AES/ECB mode observed (often risky / used in packing/obfuscation) (hits=18)",
      "source": "decryption",
      "evidence": {
        "hits": 18
      },
      "mitre": [
        "T1406"
      ]
    },
    {
      "id": "DG.DYNLOAD.DEXCLASSLOADER",
      "severity": "high",
      "reason": "Dynamic code loading pattern (DexClassLoader/PathClassLoader) (hits=3)",
      "source": "decryption",
      "evidence": {
        "hits": 3
      },
      "mitre": [
        "T1407"
      ]
    },
    {
      "id": "DG.IOC.DOMAINS_FOUND",
      "severity": "high",
      "reason": "Domains found in decrypted corpora: 500",
      "source": "decryption",
      "evidence": {
        "sample": [
          "0Alg.Alias.SecretKeyFactory",
          "0android.provider.Telephony",
          "0androidx.lifecycle.ViewModelProvider.DefaultKey",
          "0com.google.android.gms.common.internal.ICertData",
          "0com.google.android.gms.maps.internal.CreatorImpl",
          "0com.google.protobuf",
          "0com.skt.prod.dialer",
          "0com.sun.crypto.provider.TlsMasterSecretGenerator",
          "1.isArgUnused",
          "1.isVarUnused",
          "1.lambda",
          "1.processBlock",
          "12210278.false",
          "1android.settings.action",
          "1android.speech.extra"
        ]
      },
      "mitre": []
    },
    {
      "id": "DG.IOC.IPS_FOUND",
      "severity": "high",
      "reason": "IP addresses found in decrypted corpora: 6",
      "source": "decryption",
      "evidence": {
        "sample": [
          "0.0.0.0",
          "1.12.1.3",
          "1.12.1.6",
          "1.3.6.1",
          "38.181.2.17",
          "4.1.42.2"
        ]
      },
      "mitre": []
    },
    {
      "id": "DG.IOC.URLS_FOUND",
      "severity": "high",
      "reason": "URLs found in decrypted corpora: 31",
      "source": "decryption",
      "evidence": {
        "sample": [
          "http://38.181.2.17",
          "http://ns.adobe.com/xap/1.0",
          "http://record",
          "http://schemas.android.com/apk/res-auto",
          "http://schemas.android.com/apk/res/android",
          "http://xml.apache.org/xslt",
          "https://android.bugly.qq.com/rqd/async",
          "https://app-measurement.com/a",
          "https://astat.bugly.qcloud.com/rqd/async",
          "https://goo.gl/NAOOOI",
          "https://issuetracker.google.com/issues/116541301",
          "https://pagead2.googlesyndication.com/pagead/gen_204?id=gmob-apps",
          "https://plus.google.com",
          "https://www.google.com",
          "https://www.googleapis.com/auth/appstate"
        ]
      },
      "mitre": []
    },
    {
      "id": "DG.NET.C2_STRINGS",
      "severity": "high",
      "reason": "C2-like strings: /gate, /panel, /api, /cmd, /upload, /pull, /beacon patterns (hits=206)",
      "source": "decryption",
      "evidence": {
        "hits": 206
      },
      "mitre": [
        "T1437"
      ]
    },
    {
      "id": "DG.OVERLAY.SYSTEM_ALERT_WINDOW",
      "severity": "high",
      "reason": "Overlay permission / draw over other apps indicators (hits=2)",
      "source": "decryption",
      "evidence": {
        "hits": 2
      },
      "mitre": [
        "T1628"
      ]
    },
    {
      "id": "DG.PACK.ZLIB_GZIP",
      "severity": "high",
      "reason": "Compression/decompression usage (zlib/gzip) typical in packed blobs (hits=530)",
      "source": "decryption",
      "evidence": {
        "hits": 530
      },
      "mitre": [
        "T1406"
      ]
    },
    {
      "id": "DG.ABUSE.CALL_LOG",
      "severity": "medium",
      "reason": "Call log / phone state access hints (hits=20)",
      "source": "decryption",
      "evidence": {
        "hits": 20
      },
      "mitre": [
        "T1430"
      ]
    },
    {
      "id": "DG.ANTI.ANALYSIS.EMULATOR",
      "severity": "medium",
      "reason": "Emulator detection keywords (goldfish/ranchu/qemu/genymotion) (hits=9)",
      "source": "decryption",
      "evidence": {
        "hits": 9
      },
      "mitre": [
        "T1622"
      ]
    },
    {
      "id": "DG.ANTI.ANALYSIS.ROOT",
      "severity": "medium",
      "reason": "Root detection keywords (su/magisk/xposed) (hits=40)",
      "source": "decryption",
      "evidence": {
        "hits": 40
      },
      "mitre": [
        "T1622"
      ]
    },
    {
      "id": "DG.CRYPTO.KEY_IV_HINT",
      "severity": "medium",
      "reason": "Hardcoded key/iv-like strings hinted (key/iv/secret/salt) (hits=1822)",
      "source": "decryption",
      "evidence": {
        "hits": 1822
      },
      "mitre": [
        "T1406"
      ]
    },
    {
      "id": "DG.IOC.EMAILS_FOUND",
      "severity": "medium",
      "reason": "Emails found in decrypted corpora: 3",
      "source": "decryption",
      "evidence": {
        "sample": [
          "android@android.com",
          "p@F.Ceq",
          "u0013android@android.com"
        ]
      },
      "mitre": []
    },
    {
      "id": "DG.NET.CERT_PINNING_HINT",
      "severity": "medium",
      "reason": "Certificate pinning / custom trust manager hints (hits=143)",
      "source": "decryption",
      "evidence": {
        "hits": 143
      },
      "mitre": [
        "T1636"
      ]
    },
    {
      "id": "DG.PACK.BASE64",
      "severity": "medium",
      "reason": "Base64 encode/decode usage (possible packing/obfuscation stage) (hits=54)",
      "source": "decryption",
      "evidence": {
        "hits": 54
      },
      "mitre": [
        "T1406"
      ]
    },
    {
      "id": "DG.REFLECTION.CALLS",
      "severity": "medium",
      "reason": "Reflection usage pattern (Class.forName/loadClass/invoke) (hits=384)",
      "source": "decryption",
      "evidence": {
        "hits": 384
      },
      "mitre": [
        "T1406"
      ]
    },
    {
      "id": "DG.NET.OKHTTP_RETROFIT",
      "severity": "info",
      "reason": "Popular HTTP client libraries observed (OkHttp/Retrofit) - context indicator (hits=39)",
      "source": "decryption",
      "evidence": {
        "hits": 39
      },
      "mitre": []
    }
  ],
  "hidden_app_detection": {
    "present": false,
    "confidence": "low",
    "score": 0,
    "summary": "No sufficient hidden-app tags detected.",
    "signals": [],
    "tags": [],
    "reasons": [],
    "package_state": {
      "installed": false,
      "hidden": false,
      "suspended": false,
      "stopped": false,
      "notLaunched": false,
      "enabled_state": "",
      "enabled_raw": null,
      "enabled_raw_int": null
    },
    "entrypoints": {
      "has_launcher_activity": false,
      "launcher_candidates": [],
      "has_deeplink_browsable": false,
      "deeplink_schemes": [],
      "scheme_targets": {},
      "view_browsable_targets": [],
      "fallback_notes": [
        "dumpsys file not found"
      ]
    },
    "disabled_components": [],
    "disabled_activities": [],
    "disabled_component_reasons": [],
    "mitre": {
      "techniques": [],
      "notes": []
    },
    "inputs": {
      "dumpsys": {
        "present": false,
        "path": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/runtime/dumpsys_package.txt",
        "source": "manual_or_pipeline"
      },
      "apktool_dir": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/apktool",
      "jadx_dir": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/jadx"
    }
  },
  "decryption": {
    "_note": "Decryption metadata only. Key is NOT stored. Scanner reads decrypted artifacts if present.",
    "paths": {
      "root": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/artifacts/decrypted",
      "dex": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/artifacts/decrypted/classes.fixed.dex",
      "jadx": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/artifacts/decrypted/jadx",
      "smali": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/artifacts/decrypted/smali_fixed"
    },
    "result": {
      "_status": "ok",
      "reason": "",
      "inputs": {
        "dex": "/Users/goorm/Downloads/android/Deep_Guard_Semi_2_B/out_runs_b/7a/artifacts/decrypted/classes.fixed.dex",
        "jadx_files": 2500,
        "smali_files": 0
      },
      "iocs": {
        "urls": [
          "http://38.181.2.17",
          "http://ns.adobe.com/xap/1.0",
          "http://record",
          "http://schemas.android.com/apk/res-auto",
          "http://schemas.android.com/apk/res/android",
          "http://xml.apache.org/xslt",
          "https://android.bugly.qq.com/rqd/async",
          "https://app-measurement.com/a",
          "https://astat.bugly.qcloud.com/rqd/async",
          "https://goo.gl/NAOOOI",
          "https://issuetracker.google.com/issues/116541301",
          "https://pagead2.googlesyndication.com/pagead/gen_204?id=gmob-apps",
          "https://plus.google.com",
          "https://www.google.com",
          "https://www.googleapis.com/auth/appstate",
          "https://www.googleapis.com/auth/datastoremobile",
          "https://www.googleapis.com/auth/drive.appdata",
          "https://www.googleapis.com/auth/drive.file",
          "https://www.googleapis.com/auth/fitness.activity.read",
          "https://www.googleapis.com/auth/fitness.activity.write",
          "https://www.googleapis.com/auth/fitness.body.read",
          "https://www.googleapis.com/auth/fitness.body.write",
          "https://www.googleapis.com/auth/fitness.location.read",
          "https://www.googleapis.com/auth/fitness.location.write",
          "https://www.googleapis.com/auth/fitness.nutrition.read",
          "https://www.googleapis.com/auth/fitness.nutrition.write",
          "https://www.googleapis.com/auth/games",
          "https://www.googleapis.com/auth/games_lite",
          "https://www.googleapis.com/auth/plus.login",
          "https://www.googleapis.com/auth/plus.me",
          "https://www.reddit.com/user/No_Double2876/about.json?redditWebClient=web2x&app=web2x-client-production&gilding_detail=1&awarded_detail=1&raw_json=1"
        ],
        "domains": [
          "0Alg.Alias.SecretKeyFactory",
          "0android.provider.Telephony",
          "0androidx.lifecycle.ViewModelProvider.DefaultKey",
          "0com.google.android.gms.common.internal.ICertData",
          "0com.google.android.gms.maps.internal.CreatorImpl",
          "0com.google.protobuf",
          "0com.skt.prod.dialer",
          "0com.sun.crypto.provider.TlsMasterSecretGenerator",
          "1.isArgUnused",
          "1.isVarUnused",
          "1.lambda",
          "1.processBlock",
          "12210278.false",
          "1android.settings.action",
          "1android.speech.extra",
          "1androidx.core.app.NotificationCompat",
          "1com.bumptech.glide.load.resource.bitmap.FitCenter",
          "1com.google.android.gms.dynamite",
          "1com.google.android.gms.location.ILocationCallback",
          "1com.google.android.gms.location.ILocationListener",
          "1com.google.android.gms.measurement.AppMeasurement",
          "2.hasNext",
          "2.next",
          "2Alg.Alias.AlgorithmParameters",
          "2Alg.Alias.SecretKeyFactory",
          "2MeasurementServiceConnection.onConnectionSuspended",
          "2MeasurementServiceConnection.onServiceDisconnected",
          "2MediaServiceConnection.onServiceDisconnected",
          "2android.support.v4.media.session.action",
          "2androidx.lifecycle.BundlableSavedStateRegistry.key",
          "2com.bumptech.glide.load.resource.bitmap.CenterCrop",
          "2com.google.android.gms.flags.impl.FlagProviderImpl",
          "2com.google.firebase.messaging",
          "2com.tencent.feedback.eup.jni.NativeExceptionUpload",
          "3---.ZKZi",
          "3Alg.Alias.KeyPairGenerator.OID",
          "3Alg.Alias.SecretKeyFactory.OID",
          "3androidx.activity.result.contract.extra.PERMISSIONS",
          "3androidx.core.app.NotificationCompat",
          "3com.android.internal.os.RuntimeInit",
          "3com.google.android.gms.ads.identifier.service.START",
          "3com.google.android.gms.common.internal.ICancelToken",
          "3com.google.android.gms.common.stats",
          "3com.google.android.gms.signin.internal.hostedDomain",
          "3com.google.android.gms.tagmanager.TagManagerService",
          "3com.google.android.location.intent.extra.transition",
          "3com.tencent.bugly.BuglyBroadcastReceiver.permission",
          "4Alg.Alias.SecretKeyFactory.OID",
          "4android.support.v4.media.session.action",
          "4androidx.core.app.NotificationCompat",
          "4com.bumptech.glide.load.resource.bitmap.CenterInside",
          "4com.bumptech.glide.load.resource.bitmap.CircleCrop",
          "4com.google.android.gms.common.GoogleCertificatesImpl",
          "4com.google.android.gms.common.account",
          "4com.google.android.gms.common.internal.IGmsCallbacks",
          "4com.sun.crypto.provider",
          "5.BL",
          "5Alg.Alias.AlgorithmParameters",
          "5K.x.K.KKKMK",
          "5android.settings",
          "5android.support.v4.media.description",
          "5android.support.v4.media.session.action",
          "5com.google.android.gms.location",
          "5com.google.android.gms.maps.internal.IMapViewDelegate",
          "5com.google.android.gms.signin.internal.ISignInService",
          "5com.google.android.gms.signin.internal.serverClientId",
          "5com.sun.crypto.provider.KeyGeneratorCore",
          "6Alg.Alias.AlgorithmParameters.OID",
          "6Alg.Alias.SecretKeyFactory.OID",
          "6android.support.v4.media.session",
          "6android.support.v4.media.session.action",
          "6com.bumptech.glide.load.resource.bitmap.RoundedCorners",
          "6com.google.android.gms.dynamiteloader",
          "6com.google.android.location.intent.extra",
          "6com.sun.crypto.provider",
          "6com.sun.crypto.provider.PBEKeyFactory",
          "6measurement.upload",
          "7android.permission",
          "7android.support.v4.media.session.action",
          "7android.support.v4.media.session.command",
          "7com.google.android.gms.actions",
          "7com.google.android.gms.common.internal.IAccountAccessor",
          "7com.google.android.gms.common.stats.GmsCoreStatsService",
          "7com.google.android.gms.maps.internal.IGoogleMapDelegate",
          "7com.google.android.gms.maps.internal.IInfoWindowAdapter",
          "7com.google.android.gms.signin.internal.ISignInCallbacks",
          "7com.google.android.gms.signin.internal.idTokenRequested",
          "7com.google.android.wearable.compat.extra",
          "7com.google.firebase.messaging",
          "7com.samsung.android.incallui",
          "8android.support.v4.media.session.action",
          "8android.telecom.extra",
          "8com.google.android.gms.common.internal.IGmsServiceBroker",
          "8com.google.android.gms.common.ui.SignInButtonCreatorImpl",
          "8com.google.android.gms.location",
          "8com.google.android.gms.maps.internal.ICancelableCallback",
          "8com.google.android.gms.maps.internal.IOnMapClickListener",
          "8com.google.android.gms.maps.internal.IOnMapReadyCallback",
          "8com.google.android.gms.maps.internal.IOnPoiClickListener",
          "8com.google.android.gms.maps.internal.IProjectionDelegate",
          "8com.google.android.gms.maps.internal.IUiSettingsDelegate",
          "8com.google.android.gms.measurement.AppMeasurementService",
          "8com.google.android.gtalkservice.permission",
          "8com.google.firebase.messaging",
          "8com.sun.crypto.provider.KeyGeneratorCore",
          "9Alg.Alias.AlgorithmParameters.OID",
          "9android.support.v4.media.session.IMediaControllerCallback",
          "9android.support.v4.media.session.action",
          "9android.support.v4.media.session.command",
          "9android.view.accessibility.action",
          "9com.google.android.gms.maps.internal.IMapFragmentDelegate",
          "9com.google.android.gms.maps.internal.IOnMapLoadedCallback",
          "9com.google.android.gms.measurement.AppMeasurementReceiver",
          "A.length",
          "AESCipher.class",
          "AESKeyGenerator.class",
          "AESWrapCipher.class",
          "AImageReceiver.addImageRequest",
          "ARCFOURCipher.class",
          "ARCFOURKeyGenerator.class",
          "Aandroid.bluetooth.headset.profile.action",
          "Aandroidx.core.view.inputmethod.InputConnectionCompat",
          "AbsActionBarView.super.setVisibility",
          "AbsActionBarView.this",
          "AbsListView.LayoutParams",
          "AbsListView.OnScrollListener",
          "AbsListView.SelectionBoundsAdjuster",
          "AbsListView.class.getDeclaredField",
          "AbstractMap.SimpleEntry",
          "AbstractMap.SimpleImmutableEntry",
          "AccessController.doPrivileged",
          "AccessibilityDelegateCompat.getActionList",
          "AccessibilityEvent.obtain",
          "AccessibilityManager.class",
          "AccessibilityNodeInfo.AccessibilityAction",
          "AccessibilityNodeInfo.CollectionInfo",
          "AccessibilityNodeInfo.CollectionInfo.obtain",
          "AccessibilityNodeInfo.CollectionItemInfo",
          "AccessibilityNodeInfo.CollectionItemInfo.obtain",
          "AccessibilityNodeInfo.RangeInfo",
          "AccessibilityNodeInfo.RangeInfo.obtain",
          "AccessibilityNodeInfo.obtain",
          "AccessibilityNodeInfo.roleDescription",
          "AccessibilityNodeInfoCompat.CollectionInfoCompat",
          "AccessibilityNodeInfoCompat.CollectionItemInfoCompat",
          "AccessibilityViewCommand.CommandArguments",
          "AccessibilityViewCommand.MoveAtGranularityArguments.class",
          "AccessibilityViewCommand.MoveHtmlArguments.class",
          "AccessibilityViewCommand.MoveWindowArguments.class",
          "AccessibilityViewCommand.ScrollToPositionArguments.class",
          "AccessibilityViewCommand.SetProgressArguments.class",
          "AccessibilityViewCommand.SetSelectionArguments.class",
          "AccessibilityViewCommand.SetTextArguments.class",
          "AccessibleObject.class.getDeclaredField",
          "Account.CREATOR",
          "AccountManager.class",
          "Acom.bumptech.glide.load.resource.bitmap.Downsampler.FixBitmapSize",
          "Acom.google.android.gms.clearcut.internal.IClearcutLoggerCallbacks",
          "Acom.google.android.gms.maps.internal",
          "Acom.google.android.gms.maps.model.internal.IGroundOverlayDelegate",
          "Acom.google.android.gms.signin.internal",
          "ActionBar.LayoutParams",
          "ActionBar.OnMenuVisibilityListener",
          "ActionBar.OnNavigationListener",
          "ActionBar.Tab",
          "ActionBar.TabListener",
          "ActionBar.class.getDeclaredMethod",
          "ActionBarDrawerToggle.Delegate",
          "ActionBarDrawerToggle.DelegateProvider",
          "ActionBarDrawerToggleHoneycomb.SetIndicatorInfo",
          "ActionBarOverlayLayout.this",
          "ActionBarOverlayLayout.this.f.getHeight",
          "ActionMenuItemView.PopupCallback",
          "ActionMenuItemView.this",
          "ActionMenuPresenter.this",
          "ActionMenuView.ActionMenuChildView",
          "ActionMenuView.OnMenuItemClickListener",
          "ActionMenuView.this",
          "ActionMode.Callback",
          "ActionProvider.SubUiVisibilityListener",
          "ActionProvider.VisibilityListener",
          "Activity.class",
          "Activity.class.getDeclaredField",
          "ActivityChooserModel.OnChooseActivityListener",
          "ActivityChooserModel.class.getSimpleName",
          "ActivityChooserModel.this",
          "ActivityChooserModel.this.d.openFileOutput",
          "ActivityChooserView.this",
          "ActivityChooserView.this.c.notifyDataSetChanged",
          "ActivityChooserView.this.c.notifyDataSetInvalidated",
          "ActivityChooserView.this.getContext",
          "ActivityChooserView.this.getListPopupWindow",
          "ActivityChooserView.this.isShown",
          "ActivityManager.RunningAppProcessInfo",
          "ActivityManager.RunningServiceInfo",
          "ActivityManager.class",
          "ActivityRecognition.API",
          "ActivityRecognition.ActivityRecognitionApi.removeActivityUpdates",
          "ActivityRecognition.ActivityRecognitionApi.requestActivityUpdates",
          "ActivityRecognition.ActivityRecognitionApi.zza",
          "ActivityRecognition.zza",
          "ActivityRecognitionResult.class",
          "ActivityRecreator.d.invoke",
          "ActivityRecreator.e.invoke",
          "ActivityResultContract.SynchronousResult",
          "ActivityResultContracts.StartActivityForResult",
          "ActivityResultRegistry.this",
          "ActivityResultRegistry.this.c.get",
          "ActivityResultRegistry.this.e.add",
          "ActivityResultRegistry.this.f.put",
          "ActivityResultRegistry.this.f.remove",
          "ActivityResultRegistry.this.g.containsKey",
          "ActivityResultRegistry.this.g.get",
          "ActivityResultRegistry.this.g.remove",
          "ActivityResultRegistry.this.h.getParcelable",
          "ActivityResultRegistry.this.h.remove",
          "ActivityTransition.CREATOR",
          "ActivityTransition.zza",
          "ActivityTransitionEvent.CREATOR",
          "ActivityTransitionRequest.class",
          "ActivityTransitionResult.class",
          "AdapterHelper.Callback",
          "AdapterHelper.UpdateOp",
          "AdapterView.OnItemClickListener",
          "AdapterView.OnItemSelectedListener",
          "AdvertisingIdClient.Info",
          "AdvertisingIdClient.getAdvertisingIdInfo",
          "AlarmManager.class",
          "AlertController.AlertParams",
          "AlertController.this",
          "AlertDialog.Builder",
          "AlertParams.this",
          "AlertParams.this.J.onClick",
          "AlertParams.this.b.inflate",
          "AlertParams.this.x.onClick",
          "Alg.Alias",
          "Alg.Alias.AlgorithmParameterGenerator.DH",
          "Alg.Alias.AlgorithmParameterGenerator.OID",
          "Alg.Alias.AlgorithmParameters",
          "Alg.Alias.AlgorithmParameters.DH",
          "Alg.Alias.AlgorithmParameters.OID",
          "Alg.Alias.AlgorithmParameters.Rijndael",
          "Alg.Alias.AlgorithmParameters.TripleDES",
          "Alg.Alias.Cipher",
          "Alg.Alias.Cipher.OID",
          "Alg.Alias.Cipher.Rijndael",
          "Alg.Alias.Cipher.TripleDES",
          "Alg.Alias.KeyAgreement",
          "Alg.Alias.KeyAgreement.DH",
          "Alg.Alias.KeyAgreement.OID",
          "Alg.Alias.KeyFactory",
          "Alg.Alias.KeyFactory.DH",
          "Alg.Alias.KeyFactory.OID",
          "Alg.Alias.KeyGenerator",
          "Alg.Alias.KeyGenerator.Rijndael",
          "Alg.Alias.KeyGenerator.TripleDES",
          "Alg.Alias.KeyPairGenerator",
          "Alg.Alias.KeyPairGenerator.DH",
          "Alg.Alias.KeyPairGenerator.OID",
          "Alg.Alias.SecretKeyFactory",
          "Alg.Alias.SecretKeyFactory.OID",
          "Alg.Alias.SecretKeyFactory.PBE",
          "Alg.Alias.SecretKeyFactory.TripleDES",
          "AlgorithmId.get",
          "AlgorithmId.parse",
          "AlgorithmParameterGenerator.DiffieHellman",
          "AlgorithmParameterGenerator.getInstance",
          "AlgorithmParameters.AES",
          "AlgorithmParameters.Blowfish",
          "AlgorithmParameters.DES",
          "AlgorithmParameters.DESede",
          "AlgorithmParameters.DiffieHellman",
          "AlgorithmParameters.OAEP",
          "AlgorithmParameters.PBE",
          "AlgorithmParameters.getInstance",
          "AndroidAudioManager.ICallback",
          "AndroidAudioManager.TAG",
          "AndroidAudioManager.class.getSimpleName",
          "AndroidAudioManager.this",
          "AndroidAudioManager.this.headsetPluginChanged",
          "AndroidAudioManager.this.mBluetoothDevices.add",
          "AndroidAudioManager.this.mBluetoothDevices.contains",
          "AndroidAudioManager.this.mBluetoothDevices.remove",
          "AndroidAudioManager.this.mBluetoothHeadset",
          "AndroidAudioManager.this.mBluetoothHeadset.getConnectedDevices",
          "AndroidAudioManager.this.mCheckBluetoothRunnable",
          "AndroidAudioManager.this.mConnectedHeadset",
          "AndroidAudioManager.this.mHandler.postDelayed",
          "AndroidAudioManager.this.mIsCountDownOn",
          "AndroidAudioManager.this.mIsOnHeadsetSco",
          "AndroidAudioManager.this.mTurnOffSpeakerRunnable",
          "AndroidAudioManager.this.onHeadsetConnected",
          "AndroidAudioManager.this.onHeadsetDisconnected",
          "AndroidAudioManager.this.onScoAudioConnected",
          "AndroidAudioManager.this.onScoAudioDisconnected",
          "AndroidAudioManager.this.removeAllHeadsets",
          "AndroidAudioManager.this.setAudio",
          "AndroidAudioManager.this.startSco",
          "AndroidAudioManager.this.stopConnectToSco",
          "AndroidAudioManager.this.unlink",
          "AndroidManifest.xml",
          "AndroidSdkUtils.hasLollipop",
          "AndroidSdkUtils.hasP",
          "AndroidViewModel.class.isAssignableFrom",
          "Animatable2.AnimationCallback",
          "Animatable2Compat.AnimationCallback",
          "AnimatedStateListDrawableCompat.class.getSimpleName",
          "AnimatedVectorDrawableCompat.this.invalidateSelf",
          "AnimatedVectorDrawableCompat.this.scheduleSelf",
          "AnimatedVectorDrawableCompat.this.unscheduleSelf",
          "Animation.AnimationListener",
          "AnimationCallback.this.onAnimationEnd",
          "AnimationCallback.this.onAnimationStart",
          "AnimationHandler.AnimationFrameCallback",
          "AnimationHandler.this",
          "AnimationHandler.this.b.size",
          "AnimationUtils.loadAnimation",
          "AnimationUtils.loadInterpolator",
          "Animator.AnimatorListener",
          "AnimatorInflater.loadAnimator",
          "AnonymousClass1.this",
          "AnonymousClass1.this.c.get",
          "AnonymousClass1.this.c.size",
          "AnonymousClass1.this.d.get",
          "AnonymousClass1.this.d.size",
          "AnonymousClass2.this",
          "AnonymousClass4.this",
          "Api.ApiOptions",
          "Api.ApiOptions.NoOptions",
          "Api.ApiOptions.Optional",
          "Api.zza",
          "Api.zzb",
          "Api.zzc",
          "Api.zze",
          "Api.zzf",
          "AppCompatActivity.this",
          "AppCompatActivity.this.getSavedStateRegistry",
          "AppCompatDelegateImpl.this",
          "AppCompatDelegateImpl.this.g.registerReceiver",
          "AppCompatDelegateImpl.this.g.unregisterReceiver",
          "AppCompatDelegateImpl.this.r.getParent",
          "AppCompatDelegateImpl.this.r.sendAccessibilityEvent",
          "AppCompatDelegateImpl.this.r.setAlpha",
          "AppCompatDelegateImpl.this.r.setVisibility",
          "AppCompatDialog.this.superDispatchKeyEvent",
          "AppCompatSpinner.this",
          "AppCompatSpinner.this.getContext",
          "AppCompatSpinner.this.getInternalPopup",
          "AppCompatSpinner.this.getOnItemClickListener",
          "AppCompatSpinner.this.getPaddingLeft",
          "AppCompatSpinner.this.getPaddingRight",
          "AppCompatSpinner.this.getPopupContext",
          "AppCompatSpinner.this.getSelectedItemPosition",
          "AppCompatSpinner.this.getViewTreeObserver",
          "AppCompatSpinner.this.getWidth",
          "AppCompatSpinner.this.j.left",
          "AppCompatSpinner.this.j.right",
          "AppCompatSpinner.this.performItemClick",
          "AppCompatSpinner.this.setSelection",
          "AppCompatTextHelper.this",
          "AppMeasurement.ConditionalUserProperty",
          "AppMeasurement.Event",
          "AppMeasurement.Event.zza",
          "AppMeasurement.Event.zzb",
          "AppMeasurement.EventInterceptor",
          "AppMeasurement.OnEventListener",
          "AppMeasurement.Param.TIMESTAMP",
          "AppMeasurement.Param.TYPE",
          "AppMeasurement.Param.zza",
          "AppMeasurement.Param.zzb",
          "AppMeasurement.UserProperty",
          "AppMeasurement.UserProperty.zza",
          "AppMeasurement.UserProperty.zzb",
          "AppMeasurement.class.getCanonicalName",
          "AppMeasurement.class.getDeclaredMethod",
          "AppMeasurement.getInstance",
          "AppMeasurement.zza",
          "AppOpsManager.class",
          "AppOpsManager.permissionToOp",
          "AppWidgetManager.class",
          "Application.class",
          "ArchTaskExecutor.class",
          "Array.get",
          "Array.getLength",
          "Array.newInstance",
          "Array.set",
          "ArrayList.class",
          "ArrayList.java",
          "ArrayMap.this",
          "ArrayMap.this.clear",
          "ArrayMap.this.indexOfKey",
          "ArrayMap.this.indexOfValue",
          "ArrayMap.this.mArray",
          "ArrayMap.this.mSize",
          "ArrayMap.this.put",
          "ArrayMap.this.removeAt",
          "ArrayMap.this.setValueAt",
          "ArrayRow.ArrayRowVariables",
          "ArraySet.class",
          "ArraySet.this",
          "ArraySet.this.add",
          "ArraySet.this.clear",
          "ArraySet.this.indexOf",
          "ArrayTypeAdapter.FACTORY",
          "Arrays.asList",
          "Arrays.binarySearch",
          "Arrays.copyOf",
          "Arrays.copyOfRange",
          "Arrays.deepEquals",
          "Arrays.deepHashCode",
          "Arrays.equals",
          "Arrays.fill",
          "Arrays.hashCode",
          "Arrays.sort",
          "Arrays.toString",
          "AssetManager.AssetInputStream",
          "AssetManager.class",
          "AsyncListDiffer.ListListener",
          "AsyncTaskLoader.this",
          "AtomicBoolean.class",
          "AtomicInteger.class",
          "AtomicIntegerArray.class",
          "AtomicLong.class",
          "AtomicLongArray.class",
          "AttributeSet.class",
          "AttributeType.values",
          "Attributes.Name",
          "AudioAttributes.Builder",
          "AudioManager.class",
          "AudioTrack.getMinBufferSize",
          "AudioTrack.write",
          "AutoCompleteTextView.Validator",
          "AutoCompleteTextView.class.getDeclaredMethod",
          "AutoCompleteTextView.class.getMethod",
          "AutoNightModeManager.this",
          "AutoScrollHelper.this",
          "BackStackState.CREATOR",
          "Bandroidx.core.view.inputmethod.EditorInfoCompat",
          "Bandroidx.core.view.inputmethod.InputConnectionCompat",
          "Base64.decode",
          "Base64.encodeToString",
          "BaseObservableField.this.notifyChange",
          "Basic.NickName",
          "BasicMeasure.Measure",
          "BasicMeasure.Measurer",
          "BatteryManager.class",
          "Bcom.google.android.gms.maps.internal",
          "Bcom.google.android.gms.maps.model.internal.IIndoorBuildingDelegate",
          "BigDecimal.class",
          "BigInteger.ONE",
          "BigInteger.ZERO",
          "BigInteger.class",
          "BigInteger.valueOf",
          "Binder.class",
          "Binder.clearCallingIdentity",
          "Binder.flushPendingCommands",
          "Binder.getCallingPid",
          "Binder.getCallingUid",
          "Binder.restoreCallingIdentity",
          "BitSet.class",
          "Bitmap.CREATOR",
          "Bitmap.CompressFormat.JPEG",
          "Bitmap.CompressFormat.PNG",
          "Bitmap.Config",
          "Bitmap.createBitmap",
          "BitmapDescriptorFactory.zza",
          "BitmapFactory.Options",
          "BitmapFactory.decodeByteArray",
          "BitmapFactory.decodeFile",
          "BitmapFactory.decodeFileDescriptor",
          "BitmapFactory.decodeStream",
          "BlendMode.CLEAR",
          "BlendMode.COLOR",
          "BlendMode.DARKEN",
          "BlendMode.DIFFERENCE",
          "BlendMode.DST",
          "BlendMode.EXCLUSION",
          "BlendMode.HUE",
          "BlendMode.LIGHTEN",
          "BlendMode.LUMINOSITY",
          "BlendMode.MODULATE",
          "BlendMode.MULTIPLY",
          "BlendMode.OVERLAY",
          "BlendMode.PLUS",
          "BlendMode.SATURATION",
          "BlendMode.SCREEN",
          "BlendMode.SRC",
          "BlendMode.XOR",
          "BlendModeCompat.CLEAR.ordinal",
          "BlendModeCompat.COLOR.ordinal",
          "BlendModeCompat.DARKEN.ordinal",
          "BlendModeCompat.DIFFERENCE.ordinal",
          "BlendModeCompat.DST.ordinal",
          "BlendModeCompat.EXCLUSION.ordinal",
          "BlendModeCompat.HUE.ordinal",
          "BlendModeCompat.LIGHTEN.ordinal",
          "BlendModeCompat.LUMINOSITY.ordinal",
          "BlendModeCompat.MODULATE.ordinal",
          "BlendModeCompat.MULTIPLY.ordinal",
          "BlendModeCompat.OVERLAY.ordinal"
        ],
        "ips": [
          "0.0.0.0",
          "1.12.1.3",
          "1.12.1.6",
          "1.3.6.1",
          "38.181.2.17",
          "4.1.42.2"
        ],
        "emails": [
          "android@android.com",
          "p@F.Ceq",
          "u0013android@android.com"
        ],
        "user_agents": [],
        "http_hosts": [],
        "sni_hosts": []
      },
      "keyword_hits": {
        "DG.DYNLOAD.DEXCLASSLOADER": 3,
        "DG.REFLECTION.CALLS": 384,
        "DG.CRYPTO.AES_ECB": 18,
        "DG.PACK.BASE64": 54,
        "DG.PACK.ZLIB_GZIP": 530,
        "DG.CRYPTO.KEY_IV_HINT": 1822,
        "DG.NET.OKHTTP_RETROFIT": 39,
        "DG.NET.C2_STRINGS": 206,
        "DG.NET.CERT_PINNING_HINT": 143,
        "DG.OVERLAY.SYSTEM_ALERT_WINDOW": 2,
        "DG.ACCESSIBILITY.SERVICE": 19,
        "DG.ANTI.ANALYSIS.ROOT": 40,
        "DG.ANTI.ANALYSIS.EMULATOR": 9,
        "DG.ANTI.ANALYSIS.FRIDA": 2,
        "DG.ABUSE.SMS_SEND": 3,
        "DG.ABUSE.CALL_LOG": 20
      },
      "tags": [
        {
          "id": "DG.ABUSE.SMS_SEND",
          "severity": "high",
          "reason": "SMS sending APIs hinted (hits=3)",
          "source": "decryption",
          "mitre": [
            "T1412"
          ],
          "evidence": {
            "hits": 3
          }
        },
        {
          "id": "DG.ACCESSIBILITY.SERVICE",
          "severity": "high",
          "reason": "AccessibilityService usage indicators (potential abuse) (hits=19)",
          "source": "decryption",
          "mitre": [
            "T1638"
          ],
          "evidence": {
            "hits": 19
          }
        },
        {
          "id": "DG.ANTI.ANALYSIS.FRIDA",
          "severity": "high",
          "reason": "Frida detection keywords (frida-server/gadget) (hits=2)",
          "source": "decryption",
          "mitre": [
            "T1622"
          ],
          "evidence": {
            "hits": 2
          }
        },
        {
          "id": "DG.CRYPTO.AES_ECB",
          "severity": "high",
          "reason": "AES/ECB mode observed (often risky / used in packing/obfuscation) (hits=18)",
          "source": "decryption",
          "mitre": [
            "T1406"
          ],
          "evidence": {
            "hits": 18
          }
        },
        {
          "id": "DG.DYNLOAD.DEXCLASSLOADER",
          "severity": "high",
          "reason": "Dynamic code loading pattern (DexClassLoader/PathClassLoader) (hits=3)",
          "source": "decryption",
          "mitre": [
            "T1407"
          ],
          "evidence": {
            "hits": 3
          }
        },
        {
          "id": "DG.NET.C2_STRINGS",
          "severity": "high",
          "reason": "C2-like strings: /gate, /panel, /api, /cmd, /upload, /pull, /beacon patterns (hits=206)",
          "source": "decryption",
          "mitre": [
            "T1437"
          ],
          "evidence": {
            "hits": 206
          }
        },
        {
          "id": "DG.OVERLAY.SYSTEM_ALERT_WINDOW",
          "severity": "high",
          "reason": "Overlay permission / draw over other apps indicators (hits=2)",
          "source": "decryption",
          "mitre": [
            "T1628"
          ],
          "evidence": {
            "hits": 2
          }
        },
        {
          "id": "DG.PACK.ZLIB_GZIP",
          "severity": "high",
          "reason": "Compression/decompression usage (zlib/gzip) typical in packed blobs (hits=530)",
          "source": "decryption",
          "mitre": [
            "T1406"
          ],
          "evidence": {
            "hits": 530
          }
        },
        {
          "id": "DG.ABUSE.CALL_LOG",
          "severity": "medium",
          "reason": "Call log / phone state access hints (hits=20)",
          "source": "decryption",
          "mitre": [
            "T1430"
          ],
          "evidence": {
            "hits": 20
          }
        },
        {
          "id": "DG.ANTI.ANALYSIS.EMULATOR",
          "severity": "medium",
          "reason": "Emulator detection keywords (goldfish/ranchu/qemu/genymotion) (hits=9)",
          "source": "decryption",
          "mitre": [
            "T1622"
          ],
          "evidence": {
            "hits": 9
          }
        },
        {
          "id": "DG.ANTI.ANALYSIS.ROOT",
          "severity": "medium",
          "reason": "Root detection keywords (su/magisk/xposed) (hits=40)",
          "source": "decryption",
          "mitre": [
            "T1622"
          ],
          "evidence": {
            "hits": 40
          }
        },
        {
          "id": "DG.CRYPTO.KEY_IV_HINT",
          "severity": "medium",
          "reason": "Hardcoded key/iv-like strings hinted (key/iv/secret/salt) (hits=1822)",
          "source": "decryption",
          "mitre": [
            "T1406"
          ],
          "evidence": {
            "hits": 1822
          }
        },
        {
          "id": "DG.NET.CERT_PINNING_HINT",
          "severity": "medium",
          "reason": "Certificate pinning / custom trust manager hints (hits=143)",
          "source": "decryption",
          "mitre": [
            "T1636"
          ],
          "evidence": {
            "hits": 143
          }
        },
        {
          "id": "DG.PACK.BASE64",
          "severity": "medium",
          "reason": "Base64 encode/decode usage (possible packing/obfuscation stage) (hits=54)",
          "source": "decryption",
          "mitre": [
            "T1406"
          ],
          "evidence": {
            "hits": 54
          }
        },
        {
          "id": "DG.REFLECTION.CALLS",
          "severity": "medium",
          "reason": "Reflection usage pattern (Class.forName/loadClass/invoke) (hits=384)",
          "source": "decryption",
          "mitre": [
            "T1406"
          ],
          "evidence": {
            "hits": 384
          }
        },
        {
          "id": "DG.NET.OKHTTP_RETROFIT",
          "severity": "info",
          "reason": "Popular HTTP client libraries observed (OkHttp/Retrofit) - context indicator (hits=39)",
          "source": "decryption",
          "mitre": [],
          "evidence": {
            "hits": 39
          }
        },
        {
          "id": "DG.IOC.URLS_FOUND",
          "severity": "high",
          "reason": "URLs found in decrypted corpora: 31",
          "source": "decryption",
          "mitre": [],
          "evidence": {
            "sample": [
              "http://38.181.2.17",
              "http://ns.adobe.com/xap/1.0",
              "http://record",
              "http://schemas.android.com/apk/res-auto",
              "http://schemas.android.com/apk/res/android",
              "http://xml.apache.org/xslt",
              "https://android.bugly.qq.com/rqd/async",
              "https://app-measurement.com/a",
              "https://astat.bugly.qcloud.com/rqd/async",
              "https://goo.gl/NAOOOI",
              "https://issuetracker.google.com/issues/116541301",
              "https://pagead2.googlesyndication.com/pagead/gen_204?id=gmob-apps",
              "https://plus.google.com",
              "https://www.google.com",
              "https://www.googleapis.com/auth/appstate"
            ]
          }
        },
        {
          "id": "DG.IOC.DOMAINS_FOUND",
          "severity": "high",
          "reason": "Domains found in decrypted corpora: 500",
          "source": "decryption",
          "mitre": [],
          "evidence": {
            "sample": [
              "0Alg.Alias.SecretKeyFactory",
              "0android.provider.Telephony",
              "0androidx.lifecycle.ViewModelProvider.DefaultKey",
              "0com.google.android.gms.common.internal.ICertData",
              "0com.google.android.gms.maps.internal.CreatorImpl",
              "0com.google.protobuf",
              "0com.skt.prod.dialer",
              "0com.sun.crypto.provider.TlsMasterSecretGenerator",
              "1.isArgUnused",
              "1.isVarUnused",
              "1.lambda",
              "1.processBlock",
              "12210278.false",
              "1android.settings.action",
              "1android.speech.extra"
            ]
          }
        },
        {
          "id": "DG.IOC.IPS_FOUND",
          "severity": "high",
          "reason": "IP addresses found in decrypted corpora: 6",
          "source": "decryption",
          "mitre": [],
          "evidence": {
            "sample": [
              "0.0.0.0",
              "1.12.1.3",
              "1.12.1.6",
              "1.3.6.1",
              "38.181.2.17",
              "4.1.42.2"
            ]
          }
        },
        {
          "id": "DG.IOC.EMAILS_FOUND",
          "severity": "medium",
          "reason": "Emails found in decrypted corpora: 3",
          "source": "decryption",
          "mitre": [],
          "evidence": {
            "sample": [
              "android@android.com",
              "p@F.Ceq",
              "u0013android@android.com"
            ]
          }
        }
      ]
    }
  }
}
