# JNI binds native methods by class name. Renaming NativeBridge leaves the library loading
# fine and every native check silently unresolved, so the AAR carries its own rule rather
# than relying on the host app's configuration.
-keepclasseswithmembernames,includedescriptorclasses class io.github.rootect.NativeBridge {
    native <methods>;
}
