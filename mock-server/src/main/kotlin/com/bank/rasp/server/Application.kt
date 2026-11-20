package com.bank.rasp.server

import com.bank.rasp.core.attestation.AttestationEnvelope
import com.bank.rasp.core.attestation.NonceService
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable
import java.security.SecureRandom

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module).start(wait = true)
}

// ---------- 请求/响应 DTO ----------

@Serializable
data class NonceRequest(val deviceId: String, val transactionId: String)

@Serializable
data class NonceResponse(val nonce: String, val ttlMs: Long)

@Serializable
data class TransferSubmission(
    val deviceId: String,
    val envelope: AttestationEnvelope,
    /** 服务端下单时记录的金额，用于和证明内金额比对。 */
    val expectedAmountMinor: Long? = null
)

@Serializable
data class DecisionResponse(
    val accepted: Boolean,
    val code: String,
    val reason: String,
    val serverRiskScore: Int? = null
)

@Serializable
data class RegisterKeyRequest(val deviceId: String, val publicKeyX509Base64: String)

fun Application.module() {
    install(ContentNegotiation) { json() }

    val secureRandom = SecureRandom()
    val registry = DeviceKeyRegistry()
    val nonceService = NonceService(ttlMs = 120_000, now = { System.currentTimeMillis() })
    val verification = ServerVerificationService(registry, nonceService)

    routing {
        get("/health") { call.respond(mapOf("status" to "UP")) }

        // 设备注册公钥（demo 简化；生产需带外身份核验）
        post("/devices/register") {
            val req = call.receive<RegisterKeyRequest>()
            registry.registerX509Base64(req.deviceId, req.publicKeyX509Base64)
            call.respond(mapOf("registered" to req.deviceId))
        }

        // 1) 服务端下发一次性 nonce（挑战）
        post("/nonce") {
            val req = call.receive<NonceRequest>()
            val nonce = ByteArray(16).also { secureRandom.nextBytes(it) }
                .joinToString("") { "%02x".format(it) }
            nonceService.issue(nonce)
            call.respond(NonceResponse(nonce, 120_000))
        }

        // 2) 提交带签名证明的转账，服务端验签/防重放/复算/裁决
        post("/transfer") {
            val sub = call.receive<TransferSubmission>()
            when (val d = verification.verify(sub.deviceId, sub.envelope, sub.expectedAmountMinor)) {
                is ServerVerificationService.Decision.Accept ->
                    call.respond(
                        DecisionResponse(true, "ACCEPTED", d.reason, d.serverVerdict.score)
                    )
                is ServerVerificationService.Decision.Reject ->
                    call.respond(
                        HttpStatusCode.Forbidden,
                        DecisionResponse(false, d.code, d.reason, null)
                    )
            }
        }
    }
}
