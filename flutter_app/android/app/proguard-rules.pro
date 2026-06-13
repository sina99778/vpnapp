# ============================================================================
# R8 / ProGuard rules for Secure VPN.
#
# Goal: maximize shrinking + obfuscation WITHOUT breaking:
#   • Flutter MethodChannel/EventChannel handlers
#   • the VpnService lifecycle (referenced from the manifest)
#   • JNI ↔ gomobile libbox (native calls into Java/Kotlin by exact name)
#   • our own JNI anti-tamper lib (native methods called by name)
#   • Play Integrity + Google Mobile Ads (reflection-initialized)
#
# Note: Dart code obfuscation is SEPARATE from R8 — it comes from
# `flutter build --obfuscate`. R8 only obfuscates the Java/Kotlin side.
# ============================================================================

# ---- Attributes needed for JNI, generics, and annotations ------------------
-keepattributes Signature,Exceptions,InnerClasses,EnclosingMethod
-keepattributes *Annotation*,RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations
# Keep native method+line info enough to symbolicate; line tables are mapped.
-keepattributes SourceFile,LineNumberTable

# ---- Flutter ---------------------------------------------------------------
# The Flutter Gradle plugin bundles its own consumer rules for io.flutter.**,
# but keep the embedding surface explicitly to be safe.
-keep class io.flutter.embedding.** { *; }
-keep class io.flutter.plugin.** { *; }
-keep class io.flutter.plugins.** { *; }
-dontwarn io.flutter.**

# ---- JNI: native methods must NOT be renamed (UnsatisfiedLinkError otherwise) -
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# ---- Our app's bridge classes that native/Dart invoke by exact name --------
# SecurityBridge: native (tamper.c) calls Java_app_securevpn_security_SecurityBridge_*
-keep class app.securevpn.security.SecurityBridge {
    public static <methods>;
    native <methods>;
}
# The VpnService subclass + its companion start/stop are referenced by name and
# from the manifest. R8 (unlike old ProGuard) does NOT always keep manifest
# classes' members — keep explicitly so onStartCommand/openTun survive.
-keep class app.securevpn.SingBoxVpnService { *; }
-keep class app.securevpn.MainActivity { *; }
# EventChannel.StreamHandler / inner anonymous classes used as channel handlers.
-keep class app.securevpn.**$* { *; }

# ---- gomobile / libbox JNI -------------------------------------------------
# gomobile generates Java proxies in io.nekohasekai.libbox.* that the Go runtime
# calls back into by exact method name (e.g. PlatformInterface.openTun). Renaming
# any of these breaks the native↔Java bridge. Keep the whole package + members.
-keep class io.nekohasekai.libbox.** { *; }
-keep interface io.nekohasekai.libbox.** { *; }
# Any class we write that IMPLEMENTS a libbox callback interface (e.g. the
# VpnService implementing PlatformInterface) — keep its overriding methods.
-keep class * implements io.nekohasekai.libbox.PlatformInterface { *; }
-dontwarn io.nekohasekai.libbox.**

# ---- Play Integrity / Play Core --------------------------------------------
-keep class com.google.android.play.core.integrity.** { *; }
-keep class com.google.android.play.core.** { *; }
-dontwarn com.google.android.play.core.**

# ---- Google Mobile Ads (reflection-initialized) ----------------------------
-keep class com.google.android.gms.ads.** { *; }
-keep class com.google.android.gms.common.** { *; }
-dontwarn com.google.android.gms.**

# ---- General safety --------------------------------------------------------
# Don't strip enums' valueOf/values (used via reflection by some plugins).
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
# Parcelables (Intent extras / channel codecs).
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}
