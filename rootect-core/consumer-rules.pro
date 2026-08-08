# JNI binds native methods by class name. Renaming NativeBridge leaves the library loading
# fine and every native check silently unresolved, so the AAR carries its own rule rather
# than relying on the host app's configuration.
-keepclasseswithmembernames,includedescriptorclasses class io.github.rootect.internal.jni.NativeBridge {
    native <methods>;
}

# SignalId names are a published contract — host apps persist them and forward them to
# fraud backends, so renaming them changes data those systems already store. R8 happens to
# keep them today; this makes it a guarantee rather than a coincidence.
-keepclassmembers enum io.github.rootect.** {
    <fields>;
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
