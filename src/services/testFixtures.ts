import {
  SmaliClass,
  ManifestData,
  UploadedArtifact,
  TargetBehaviorType,
} from '../types/forensics';
import { parseSmali } from './smaliParser';

export interface TestScenario {
  id: string;
  name: string;
  description: string;
  targetBehavior: TargetBehaviorType;
  observedSymptom: string;
  expectedBehavior: string;
  manifest: ManifestData;
  smaliFiles: { name: string; content: string }[];
  expectedFindingSummary: string;
}

export const TEST_SCENARIOS: TestScenario[] = [
  {
    id: 'test-a-forced-update',
    name: 'Test A — Forced Non-Dismissible Update',
    description: 'Checks remote minimum version, displays setCancelable(false) modal dialog, and launches APK download URL.',
    targetBehavior: 'forced_update',
    observedSymptom: 'Upon launch, a modal dialog blocks the screen with "Update Required" and cannot be cancelled or dismissed. Clicking OK redirects to external APK download link.',
    expectedBehavior: 'App should start up into MainDashboardActivity and allow user to continue using current version.',
    manifest: {
      packageName: 'com.modded.updater',
      versionCode: 102,
      versionName: '1.0.2',
      minSdkVersion: 21,
      targetSdkVersion: 34,
      permissions: ['android.permission.INTERNET', 'android.permission.REQUEST_INSTALL_PACKAGES'],
      components: [
        {
          type: 'activity',
          name: 'com.modded.updater.MainActivity',
          exported: true,
          intentFilters: [
            {
              actions: ['android.intent.action.MAIN'],
              categories: ['android.intent.category.LAUNCHER'],
            },
          ],
        },
      ],
      rawXml: `<manifest package="com.modded.updater">\n  <uses-permission android:name="android.permission.INTERNET"/>\n  <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>\n  <application android:label="UpdateTestApp">\n    <activity android:name=".MainActivity" android:exported="true">\n      <intent-filter>\n        <action android:name="android.intent.action.MAIN"/>\n        <category android:name="android.intent.category.LAUNCHER"/>\n      </intent-filter>\n    </activity>\n  </application>\n</manifest>`,
    },
    smaliFiles: [
      {
        name: 'smali/com/modded/updater/MainActivity.smali',
        content: `.class public Lcom/modded/updater/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

.field private currentVersion:I

.method public constructor <init>()V
    .registers 2
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    const/16 v0, 0x66
    iput v0, p0, Lcom/modded/updater/MainActivity;->currentVersion:I
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 3
    .line 20
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    .line 22
    invoke-virtual {p0}, Lcom/modded/updater/MainActivity;->checkEnforcedUpdate()V
    return-void
.end method

.method public checkEnforcedUpdate()V
    .registers 5
    .line 30
    # Simulated remote version comparison check (server required version = 200)
    const/16 v0, 0xc8
    iget v1, p0, Lcom/modded/updater/MainActivity;->currentVersion:I
    if-le v0, v1, :cond_pass

    .line 34
    # Enforce non-dismissible update modal
    new-instance v2, Landroid/app/AlertDialog$Builder;
    invoke-direct {v2, p0}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V
    
    const-string v3, "Critical Update Required"
    invoke-virtual {v2, v3}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;
    
    const-string v3, "You must download the latest APK version to continue using this app."
    invoke-virtual {v2, v3}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    # setCancelable(false) forces user into modal trap
    const/4 v3, 0x0
    invoke-virtual {v2, v3}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;

    const-string v3, "Update Now"
    new-instance v0, Lcom/modded/updater/MainActivity$UpdateClickListener;
    invoke-direct {v0, p0}, Lcom/modded/updater/MainActivity$UpdateClickListener;-><init>(Lcom/modded/updater/MainActivity;)V
    invoke-virtual {v2, v3, v0}, Landroid/app/AlertDialog$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    invoke-virtual {v2}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;

:cond_pass
    return-void
.end method

.method public launchDownloadPage()V
    .registers 4
    .line 55
    const-string v0, "https://updates.cdn-mirror-apks.net/builds/app-v2.0-mandatory.apk"
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    const-string v0, "android.intent.action.VIEW"
    invoke-direct {v2, v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V
    invoke-virtual {p0, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Confirmed: Non-dismissible AlertDialog blocks app lifecycle via setCancelable(false) and routes to external APK download link.',
  },
  {
    id: 'test-b-remote-popup',
    name: 'Test B — Remote Announcement Popup',
    description: 'Retrieves JSON payload containing title, message, and URL, dynamically binds to dialog button and launches browser.',
    targetBehavior: 'forced_popup',
    observedSymptom: 'Intermittent announcement popup shows promotional title and opens third-party browser without prior user tap.',
    expectedBehavior: 'Application launches directly without unexpected promotional dialog interruptions.',
    manifest: {
      packageName: 'com.modded.announcements',
      versionCode: 14,
      versionName: '1.4',
      permissions: ['android.permission.INTERNET'],
      components: [
        {
          type: 'activity',
          name: 'com.modded.announcements.HomeActivity',
          exported: true,
          intentFilters: [],
        },
      ],
    },
    smaliFiles: [
      {
        name: 'smali/com/modded/announcements/HomeActivity.smali',
        content: `.class public Lcom/modded/announcements/HomeActivity;
.super Landroid/app/Activity;
.source "HomeActivity.java"

.method public onResume()V
    .registers 2
    invoke-super {p0}, Landroid/app/Activity;->onResume()V
    # Triggers remote payload announcement on every resume
    invoke-virtual {p0}, Lcom/modded/announcements/HomeActivity;->fetchAndShowAnnouncement()V
    return-void
.end method

.method public fetchAndShowAnnouncement()V
    .registers 5
    # Simulated remote JSON parsing
    new-instance v0, Lorg/json/JSONObject;
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V
    
    const-string v1, "title"
    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2

    const-string v1, "message"
    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3

    const-string v1, "destination_url"
    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v4

    # Build popup dialog
    new-instance v1, Landroid/app/AlertDialog$Builder;
    invoke-direct {v1, p0}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V
    invoke-virtual {v1, v2}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;
    invoke-virtual {v1, v3}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;
    invoke-virtual {v1}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;
    
    # Auto-dispatch external link
    invoke-virtual {p0, v4}, Lcom/modded/announcements/HomeActivity;->openRemoteUrl(Ljava/lang/String;)V
    return-void
.end method

.method public openRemoteUrl(Ljava/lang/String;)V
    .registers 4
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v0
    new-instance v1, Landroid/content/Intent;
    const-string p1, "android.intent.action.VIEW"
    invoke-direct {v1, p1, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V
    invoke-virtual {p0, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Confirmed: Remote JSON payload supplies announcement title, message, and destination URL, immediately opening external browser.',
  },
  {
    id: 'test-c-dynamic-redirect',
    name: 'Test C — Dynamic Redirect via StringBuilder',
    description: 'Assembles target tracking URL at runtime using StringBuilder concatenation and dispatches ACTION_VIEW intent.',
    targetBehavior: 'forced_redirect',
    observedSymptom: 'Browser opens an obfuscated tracking redirect link shortly after application startup.',
    expectedBehavior: 'App does not initiate external browser redirects.',
    manifest: {
      packageName: 'com.modded.tracker',
      versionCode: 3,
      versionName: '1.0',
      permissions: ['android.permission.INTERNET'],
      components: [
        {
          type: 'activity',
          name: 'com.modded.tracker.SplashActivity',
          exported: true,
          intentFilters: [],
        },
      ],
    },
    smaliFiles: [
      {
        name: 'smali/com/modded/tracker/SplashActivity.smali',
        content: `.class public Lcom/modded/tracker/SplashActivity;
.super Landroid/app/Activity;
.source "SplashActivity.java"

.method public onStart()V
    .registers 2
    invoke-super {p0}, Landroid/app/Activity;->onStart()V
    invoke-virtual {p0}, Lcom/modded/tracker/SplashActivity;->dispatchAffiliateRedirect()V
    return-void
.end method

.method public dispatchAffiliateRedirect()V
    .registers 5
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    
    const-string v1, "https://redirect-gateway.analytics-route.com"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    
    const-string v1, "/track/offer?aff_id="
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    
    const-string v1, "982314&campaign=injected_apk"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v2
    
    invoke-static {v2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v3
    
    new-instance v4, Landroid/content/Intent;
    const-string v1, "android.intent.action.VIEW"
    invoke-direct {v4, v1, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V
    
    invoke-virtual {p0, v4}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Confirmed: Dynamically assembled tracking URL using StringBuilder.append() dispatched via unprompted onStart() lifecycle event.',
  },
  {
    id: 'test-d-normal-external-link',
    name: 'Test D — Normal User-Initiated External Link',
    description: 'Legitimate button click opening privacy policy or help documentation. Must NOT be classified as malicious.',
    targetBehavior: 'unexpected_external_link',
    observedSymptom: 'Clicking "Help Center" button opens the official documentation site in user browser.',
    expectedBehavior: 'Standard expected behavior; user gesture dispatches expected external URL.',
    manifest: {
      packageName: 'com.official.app',
      versionCode: 42,
      versionName: '4.2',
      permissions: ['android.permission.INTERNET'],
      components: [
        {
          type: 'activity',
          name: 'com.official.app.SettingsActivity',
          exported: false,
          intentFilters: [],
        },
      ],
    },
    smaliFiles: [
      {
        name: 'smali/com/official/app/SettingsActivity.smali',
        content: `.class public Lcom/official/app/SettingsActivity;
.super Landroid/app/Activity;
.implements Landroid/view/View$OnClickListener;
.source "SettingsActivity.java"

.method public onClick(Landroid/view/View;)V
    .registers 4
    .line 88
    # User taps "Help & Support" button
    const-string v0, "https://support.officialapp.com/help/faq"
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    const-string v0, "android.intent.action.VIEW"
    invoke-direct {v2, v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V
    invoke-virtual {p0, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Benign / Legitimate: Standard user gesture (View.OnClickListener.onClick) opens official support portal; correctly distinguished from unprompted redirect.',
  },
  {
    id: 'test-e-incomplete-evidence',
    name: 'Test E — Incomplete Evidence (Missing Callers)',
    description: 'Contains isolated navigation sink without calling triggers or destination provenance. Must be classified as Unresolved.',
    targetBehavior: 'unexpected_external_link',
    observedSymptom: 'Suspicious method signature exists in decompilation, but unknown whether it is invoked at runtime.',
    expectedBehavior: 'Forensic engine marks finding as Unresolved and specifies what missing artifacts are needed.',
    manifest: {
      packageName: 'com.modded.partial',
      versionCode: 1,
      versionName: '1.0',
      permissions: [],
      components: [],
    },
    smaliFiles: [
      {
        name: 'smali/com/modded/partial/UnusedHandler.smali',
        content: `.class public Lcom/modded/partial/UnusedHandler;
.super Ljava/lang/Object;
.source "UnusedHandler.java"

.method public launchUnresolvedRedirect(Landroid/content/Context;Ljava/lang/String;)V
    .registers 5
    # Isolated sink with missing caller and undefined URL parameter
    invoke-static {p2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v0
    new-instance v1, Landroid/content/Intent;
    const-string v2, "android.intent.action.VIEW"
    invoke-direct {v1, v2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V
    invoke-virtual {p1, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Unresolved: Method contains intent sink, but no caller is present in available classes and parameter origin is unverified. Identifies need for secondary DEX artifacts.',
  },
  {
    id: 'test-f-safe-patch',
    name: 'Test F — Safe Remediation & Patch Lab',
    description: 'Demonstrates a narrow, surgical Smali patch to neutralize an unwanted forced prompt without removing unrelated activity navigation.',
    targetBehavior: 'forced_update',
    observedSymptom: 'Forced modal update prompt in HelperService interrupts background sync.',
    expectedBehavior: 'Patch lab generates precise return-void stub, preserving Dalvik register counts and branch labels.',
    manifest: {
      packageName: 'com.modded.patchdemo',
      versionCode: 10,
      versionName: '2.0',
      permissions: ['android.permission.INTERNET'],
      components: [],
    },
    smaliFiles: [
      {
        name: 'smali/com/modded/patchdemo/HelperService.smali',
        content: `.class public Lcom/modded/patchdemo/HelperService;
.super Ljava/lang/Object;
.source "HelperService.java"

.method public static checkAndEnforce(Landroid/content/Context;)V
    .registers 3
    .line 40
    # Obtrusive forced modal trigger
    new-instance v0, Landroid/app/AlertDialog$Builder;
    invoke-direct {v0, p0}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V
    const/4 v1, 0x0
    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;
    invoke-virtual {v0}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;
    return-void
.end method

.method public static legitimateSyncOperation(Landroid/content/Context;)V
    .registers 2
    # Unrelated critical function that must NOT be broken by patch
    # Performs core user data backup
    return-void
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Safe Patch: Replaces checkAndEnforce() body with single return-void instruction while preserving legitimateSyncOperation() intact.',
  },
  {
    id: 'test-g-dex10-crash-fix',
    name: 'Test G — DEX10 Pipeline & Anti-Crash Protection (com.gold.youtube.om7753)',
    description: 'Diagnoses and fixes startup crash (ClassNotFoundException com.gold.youtube.om7753.App) caused by partial DEX replacement. Enforces 100% class dump preservation.',
    targetBehavior: 'forced_update',
    observedSymptom: 'Rebuilt APK crashes at launch: "java.lang.ClassNotFoundException: Didn\'t find class \\"com.gold.youtube.om7753.App\\"" after patching forced update in classes10.dex.',
    expectedBehavior: 'Pipeline preserves App.smali and all unmodified classes in classes10.dex. Complete DEX assembly boots cleanly without ClassNotFoundException.',
    manifest: {
      packageName: 'com.gold.youtube.om7753',
      versionCode: 7753,
      versionName: '7.7.53',
      minSdkVersion: 21,
      targetSdkVersion: 34,
      permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'],
      components: [
        {
          type: 'activity',
          name: 'com.gold.youtube.om7753.MainActivity',
          exported: true,
          intentFilters: [
            {
              actions: ['android.intent.action.MAIN'],
              categories: ['android.intent.category.LAUNCHER'],
            },
          ],
        },
      ],
      rawXml: `<manifest package="com.gold.youtube.om7753">\n  <uses-permission android:name="android.permission.INTERNET"/>\n  <application android:name=".App" android:label="GoldYouTube">\n    <activity android:name=".MainActivity" android:exported="true">\n      <intent-filter>\n        <action android:name="android.intent.action.MAIN"/>\n        <category android:name="android.intent.category.LAUNCHER"/>\n      </intent-filter>\n    </activity>\n  </application>\n</manifest>`,
    },
    smaliFiles: [
      {
        name: 'smali_classes10/com/gold/youtube/om7753/App.smali',
        content: `.class public Lcom/gold/youtube/om7753/App;
.super Landroid/app/Application;
.source "App.java"

# Critical application entrypoint class declared in manifest
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method public onCreate()V
    .registers 1
    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    return-void
.end method
.end class`,
      },
      {
        name: 'smali_classes10/com/gold/youtube/om7753/MainActivity.smali',
        content: `.class public Lcom/gold/youtube/om7753/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 3
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-static {p0}, Lcom/gold/youtube/om7753/updater/ForcedUpdateDialog;->checkUpdate(Landroid/content/Context;)V
    return-void
.end method
.end class`,
      },
      {
        name: 'smali_classes10/com/gold/youtube/om7753/updater/ForcedUpdateDialog.smali',
        content: `.class public Lcom/gold/youtube/om7753/updater/ForcedUpdateDialog;
.super Ljava/lang/Object;
.source "ForcedUpdateDialog.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static checkUpdate(Landroid/content/Context;)V
    .registers 4
    new-instance v0, Landroid/app/AlertDialog$Builder;
    invoke-direct {v0, p0}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V
    const-string v1, "Mandatory App Update"
    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;
    const/4 v1, 0x0
    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;
    invoke-virtual {v0}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;
    return-void
.end method
.end class`,
      },
      {
        name: 'smali_classes10/com/gold/youtube/om7753/network/ApiConfig.smali',
        content: `.class public Lcom/gold/youtube/om7753/network/ApiConfig;
.super Ljava/lang/Object;
.source "ApiConfig.java"

.field public static final BASE_URL:Ljava/lang/String; = "https://api.youtube-gold.net"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static getEndpoint()Ljava/lang/String;
    .registers 1
    const-string v0, "https://api.youtube-gold.net/v1"
    return-object v0
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Confirmed: Forced modal update dialog in ForcedUpdateDialog.checkUpdate(). Mandatory validation verifies App.smali is retained in classes10.dex to prevent cold-boot ClassNotFoundException.',
  },
  {
    id: 'test-h-daily-chrome-adware',
    name: 'Test H — Modded Adware: Daily Auto-Launch of Chrome (classes10.dex)',
    description: 'Injected mod adware checks 24-hour interval via System.currentTimeMillis() and launches Chrome (com.android.chrome) with external ad website.',
    targetBehavior: 'unwanted_ads_overlay',
    observedSymptom: 'Every day when opening the app, Google Chrome suddenly opens and navigates to an advertising redirect website without permission.',
    expectedBehavior: 'App starts up smoothly into main activity; Chrome is never launched in the background or foreground.',
    manifest: {
      packageName: 'com.gold.youtube.om7753',
      versionCode: 7753,
      versionName: '7.7.53',
      minSdkVersion: 21,
      targetSdkVersion: 34,
      permissions: ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE'],
      components: [
        {
          type: 'activity',
          name: 'com.gold.youtube.om7753.MainActivity',
          exported: true,
          intentFilters: [
            {
              actions: ['android.intent.action.MAIN'],
              categories: ['android.intent.category.LAUNCHER'],
            },
          ],
        },
      ],
      rawXml: `<manifest package="com.gold.youtube.om7753">\n  <uses-permission android:name="android.permission.INTERNET"/>\n  <application android:name=".App" android:label="TargetApp">\n    <activity android:name=".MainActivity" android:exported="true">\n      <intent-filter>\n        <action android:name="android.intent.action.MAIN"/>\n        <category android:name="android.intent.category.LAUNCHER"/>\n      </intent-filter>\n    </activity>\n  </application>\n</manifest>`,
    },
    smaliFiles: [
      {
        name: 'smali_classes10/com/gold/youtube/om7753/App.smali',
        content: `.class public Lcom/gold/youtube/om7753/App;
.super Landroid/app/Application;
.source "App.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method public onCreate()V
    .registers 1
    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    return-void
.end method
.end class`,
      },
      {
        name: 'smali_classes10/com/gold/youtube/om7753/MainActivity.smali',
        content: `.class public Lcom/gold/youtube/om7753/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 2
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    # Triggers daily ad check in injected classes10.dex
    invoke-static {p0}, Lcom/gold/youtube/om7753/adware/DailyChromeAd;->checkAndLaunchDailyAd(Landroid/content/Context;)V
    return-void
.end method
.end class`,
      },
      {
        name: 'smali_classes10/com/gold/youtube/om7753/adware/DailyChromeAd.smali',
        content: `.class public Lcom/gold/youtube/om7753/adware/DailyChromeAd;
.super Ljava/lang/Object;
.source "DailyChromeAd.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static checkAndLaunchDailyAd(Landroid/content/Context;)V
    .registers 8
    .line 18
    const-string v0, "mod_ad_prefs"
    const/4 v1, 0x0
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0

    const-string v1, "last_chrome_ad_timestamp"
    const-wide/16 v2, 0x0
    invoke-interface {v0, v1, v2, v3}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J
    move-result-wide v2

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J
    move-result-wide v4

    # 24 hours check
    sub-long v6, v4, v2
    const-wide/32 v2, 0x5265c00
    cmp-long v6, v6, v2
    if-gez v6, :cond_skip_ad

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    invoke-interface {v0, v1, v4, v5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    # Launch Chrome with advertisement URL
    const-string v0, "android.intent.action.VIEW"
    const-string v1, "https://ad-traffic-direct.com/offer?mod_user=1"
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    invoke-direct {v2, v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    const-string v0, "com.android.chrome"
    invoke-virtual {v2, v0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;
    const/high16 v0, 0x10000000
    invoke-virtual {v2, v0}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    invoke-virtual {p0, v2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

:cond_skip_ad
    return-void
.end method
.end class`,
      },
    ],
    expectedFindingSummary: 'Confirmed: Daily unprompted ACTION_VIEW intent targeting Chrome (com.android.chrome) detected in classes10.dex. Safe patch stubs method with return-void and preserves App.smali in DEX.',
  },
];

export function loadTestScenario(scenarioId: string): {
  targetBehavior: TargetBehaviorType;
  observedBehavior: string;
  expectedBehavior: string;
  artifacts: UploadedArtifact[];
  classes: SmaliClass[];
  manifest: ManifestData;
} {
  const scenario = TEST_SCENARIOS.find((s) => s.id === scenarioId) || TEST_SCENARIOS[0];

  const artifacts: UploadedArtifact[] = [
    {
      id: `art-manifest-${scenario.id}`,
      name: 'AndroidManifest.xml',
      size: scenario.manifest.rawXml?.length || 512,
      format: 'manifest',
      status: 'parsed',
      coverage: `Manifest verified: ${scenario.manifest.packageName}, ${scenario.manifest.permissions.length} permissions`,
      content: scenario.manifest.rawXml,
    },
    ...scenario.smaliFiles.map((f, i) => ({
      id: `art-smali-${scenario.id}-${i}`,
      name: f.name,
      size: f.content.length,
      format: 'smali' as const,
      status: 'parsed' as const,
      coverage: '100% analyzed (Smali syntax verified)',
      content: f.content,
    })),
  ];

  const classes: SmaliClass[] = [];
  for (const f of scenario.smaliFiles) {
    classes.push(...parseSmali(f.content, f.name));
  }

  return {
    targetBehavior: scenario.targetBehavior,
    observedBehavior: scenario.observedSymptom,
    expectedBehavior: scenario.expectedBehavior,
    artifacts,
    classes,
    manifest: scenario.manifest,
  };
}
