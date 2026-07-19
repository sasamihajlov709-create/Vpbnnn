# Keep attributes necessary for debugging, generics, and signatures
-keepattributes SourceFile,LineNumberTable,Signature,InnerClasses,EnclosingMethod

# Keep all classes in our main fresh package to ensure proxy logic, VPN service, and telemetry are intact
-keep class com.aistudio.pinkproxy.fresh.** { *; }
