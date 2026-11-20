package com.bank.rasp.core.policy

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FalsePositiveMitigatorTest {

    private val now = 1L
    private fun sig(id: String, conf: Double) =
        Signal(id, ThreatFamily.EMULATOR, Severity.WEAK, conf, "ev", Channel.JAVA_API, now)

    @Test
    fun `allowlist lowers confidence but never removes signal`() {
        val entries = listOf(
            AllowlistEntry("vendor-rom-x", "EMU_SENSOR_MISSING", 0.2, "该机型无陀螺仪属正常")
        )
        val mitigator = FalsePositiveMitigator(entries)
        val out = mitigator.apply("device/vendor-rom-x/user", listOf(sig("EMU_SENSOR_MISSING", 0.8)))
        assertEquals(1, out.size) // 信号仍在，可追溯
        assertEquals(0.2, out.first().confidence)
        assertTrue(out.first().evidence.contains("allowlisted"))
    }

    @Test
    fun `allowlist does not affect unmatched device`() {
        val entries = listOf(AllowlistEntry("vendor-rom-x", "EMU_SENSOR_MISSING", 0.2, "r"))
        val out = FalsePositiveMitigator(entries).apply("other/device", listOf(sig("EMU_SENSOR_MISSING", 0.8)))
        assertEquals(0.8, out.first().confidence)
    }

    @Test
    fun `allowlist never raises confidence`() {
        val entries = listOf(AllowlistEntry("*", "EMU_SENSOR_MISSING", 0.9, "r"))
        val out = FalsePositiveMitigator(entries).apply("any", listOf(sig("EMU_SENSOR_MISSING", 0.3)))
        assertEquals(0.3, out.first().confidence)
    }
}
