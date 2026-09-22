package io.github.rootect.attestation

import java.time.Duration
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CachedRevocationsTest {
    @Test
    fun usableListDoesNotWaitForAnotherRequestsRefresh() {
        var now = Instant.EPOCH
        var loads = 0
        val refreshing = CountDownLatch(1)
        val release = CountDownLatch(1)
        val cache = CachedRevocations(
            load = {
                loads++
                if (loads == 2) {
                    refreshing.countDown()
                    check(release.await(10, TimeUnit.SECONDS))
                }
                setOf("aa")
            },
            refreshAfter = Duration.ofSeconds(1),
            maxStale = Duration.ofSeconds(10),
            now = { now },
        )
        assertEquals(setOf("aa"), cache.get())
        now = now.plusSeconds(2)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val first = pool.submit<Set<String>> { cache.get() }
            assertTrue(refreshing.await(3, TimeUnit.SECONDS))
            val second = pool.submit<Set<String>> { cache.get() }
            assertEquals(setOf("aa"), second.get(3, TimeUnit.SECONDS))
            release.countDown()
            assertEquals(setOf("aa"), first.get(3, TimeUnit.SECONDS))
        } finally {
            release.countDown()
            pool.shutdownNow()
        }
    }

    @Test
    fun coldStartFailuresRespectRetryBackoff() {
        var now = Instant.EPOCH
        var loads = 0
        val cache = CachedRevocations(
            load = { loads++; throw IllegalStateException("offline") },
            retryAfter = Duration.ofSeconds(2),
            now = { now },
        )

        assertFailsWith<RevocationUnavailableException> { cache.get() }
        now = now.plusSeconds(1)
        assertFailsWith<RevocationUnavailableException> { cache.get() }
        assertEquals(1, loads)
        now = now.plusSeconds(1)
        assertFailsWith<RevocationUnavailableException> { cache.get() }
        assertEquals(2, loads)
    }

    @Test
    fun expiredCacheFailuresRespectRetryBackoff() {
        var now = Instant.EPOCH
        var loads = 0
        val cache = CachedRevocations(
            load = {
                loads++
                if (loads > 1) throw IllegalStateException("offline")
                setOf("aa")
            },
            refreshAfter = Duration.ofSeconds(1),
            maxStale = Duration.ofSeconds(10),
            retryAfter = Duration.ofSeconds(2),
            now = { now },
        )

        assertEquals(setOf("aa"), cache.get())
        now = now.plusSeconds(10)
        assertFailsWith<RevocationUnavailableException> { cache.get() }
        now = now.plusSeconds(1)
        assertFailsWith<RevocationUnavailableException> { cache.get() }
        assertEquals(2, loads)
    }

    @Test
    fun cachedListExpiringDuringFailedRefreshIsRejected() {
        var now = Instant.EPOCH
        var loads = 0
        val cache = CachedRevocations(
            load = {
                loads++
                if (loads > 1) {
                    now = now.plusSeconds(2)
                    throw IllegalStateException("timeout")
                }
                setOf("aa")
            },
            refreshAfter = Duration.ofSeconds(1),
            maxStale = Duration.ofSeconds(10),
            now = { now },
        )

        assertEquals(setOf("aa"), cache.get())
        now = now.plusSeconds(9)
        assertFailsWith<RevocationUnavailableException> { cache.get() }
    }

    @Test
    fun refreshResumesAfterBackoffAndReplacesTheList() {
        var now = Instant.EPOCH
        var loads = 0
        val cache = CachedRevocations(
            load = {
                loads++
                when (loads) {
                    1 -> setOf("aa")
                    2 -> throw IllegalStateException("offline")
                    else -> setOf("aa", "bb")
                }
            },
            refreshAfter = Duration.ofSeconds(1),
            maxStale = Duration.ofSeconds(10),
            retryAfter = Duration.ofSeconds(2),
            now = { now },
        )

        assertEquals(setOf("aa"), cache.get())
        now = now.plusSeconds(1)
        assertEquals(setOf("aa"), cache.get())
        now = now.plusSeconds(1)
        assertEquals(setOf("aa"), cache.get())
        assertEquals(2, loads)
        now = now.plusSeconds(1)
        assertEquals(setOf("aa", "bb"), cache.get())
        assertEquals(3, loads)
    }
}
