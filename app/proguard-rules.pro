# demo 不开启混淆；生产加固时至少保留以下规则，避免 JNI / 序列化被破坏
-keep class com.bank.rasp.demo.rasp.NativeFinding { *; }
-keep class com.bank.rasp.demo.rasp.NativeBridge { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class **$$serializer { *; }
-keepclasseswithmembers class com.bank.rasp.core.** {
    kotlinx.serialization.KSerializer serializer(...);
}
