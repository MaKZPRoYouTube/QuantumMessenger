# Keep crypto classes (remove reflective attack surface where possible)
-keep class com.quantummessenger.crypto.** { *; }
-dontwarn org.conscrypt.**
