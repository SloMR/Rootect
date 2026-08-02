package io.github.rootect

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Proves the JNI bridge is wired end to end on a real device.
 */
@RunWith(AndroidJUnit4::class)
class NativeBridgeTest {

    @Test
    fun nativeLayerRoundTripsAString() {
        assertEquals("rootect-native-ok", Rootect.nativePing())
    }
}
