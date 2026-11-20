package com.bank.rasp.core.attestation

/**
 * 服务端 nonce 挑战与重放防护。
 *
 * 流程：服务端为某次敏感操作签发一次性 nonce（带 TTL），客户端证明里必须原样带回；
 * 服务端在 [consume] 时原子地「校验存在 + 未过期 + 删除」，同一 nonce 第二次出现即判重放。
 *
 * 纯 Kotlin、用注入的时钟与过期判断，便于在宿主机 JVM 单测（不依赖真实时间）。
 */
class NonceService(
    private val ttlMs: Long = 120_000L,
    private val now: () -> Long
) {
    private class Issued(val atMs: Long, var consumed: Boolean = false)

    // 保留消费后的「墓碑」记录直到 TTL，这样在 TTL 内重放同一 nonce 才能识别为 Replayed，
    // 而不是因为记录已删除而退化成 Unknown（两者安全含义不同，不能混为一谈）。
    private val issued = LinkedHashMap<String, Issued>()

    /** 签发一个挑战 nonce。nonce 由调用方提供（生产用 SecureRandom），此处只管生命周期。 */
    fun issue(nonce: String) {
        evictExpired()
        issued[nonce] = Issued(now())
    }

    sealed class Result {
        data object Ok : Result()
        data object Unknown : Result()       // 从未签发 → 伪造
        data object Expired : Result()       // 超时
        data object Replayed : Result()      // TTL 内已被消费过 → 重放攻击
    }

    /** 消费 nonce；任何非 Ok 结论都应让服务端拒绝该敏感操作。 */
    fun consume(nonce: String): Result {
        // 先查记录再判断过期：不能先 evict，否则过期记录会被删成 Unknown，丢失 Expired 语义
        val record = issued[nonce] ?: return Result.Unknown
        if (now() - record.atMs > ttlMs) {
            issued.remove(nonce)
            return Result.Expired
        }
        evictExpired() // 顺手清理其它已过期记录
        if (record.consumed) return Result.Replayed
        record.consumed = true // 标记为已消费但保留为墓碑，供重放检测
        return Result.Ok
    }

    private fun evictExpired() {
        // 按签发时间从旧到新清理所有超过 TTL 的记录（含墓碑）
        val it = issued.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (now() - e.value.atMs > ttlMs) it.remove() else break
        }
    }
}

/**
 * 设备计数器回滚检测：服务端记录每台设备见过的最大 counter，
 * 证明里的 counter 必须单调不减，否则疑似回滚/克隆。
 */
class CounterGuard {
    private val maxByDevice = HashMap<String, Long>()

    sealed class Result { data object Ok : Result(); data object Rollback : Result() }

    fun check(deviceId: String, counter: Long): Result {
        val prev = maxByDevice[deviceId]
        if (prev != null && counter < prev) return Result.Rollback
        maxByDevice[deviceId] = maxOf(prev ?: counter, counter)
        return Result.Ok
    }
}
