package dev.mayi.android

import dev.mayi.ffi.ApprovalChoice
import dev.mayi.ffi.KeyException
import dev.mayi.ffi.JoinInvitation
import dev.mayi.ffi.KeyStore
import dev.mayi.ffi.joinVault
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Kotlin side against the real Rust core, on this machine's JVM: the key
 * encodings, the controller, and requests from the real `mayi` CLI. What is
 * not covered here is everything that needs Android itself: the Keystore,
 * the fingerprint prompt, the service and the screens.
 */
class ControllerTest {
    /** The same JCA calls as the Android Keystore backend, with keys in memory. */
    class TestKeys : KeyStore {
        private val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        private val device = generator.generateKeyPair()
        private val biometric = generator.generateKeyPair()
        @Volatile var allowBiometric = true
        val prompts = mutableListOf<String>()

        override fun devicePublic() = P256.encode(device.public)
        override fun biometricPublic() = P256.encode(biometric.public)
        override fun deviceEcdh(peerPublic: ByteArray) = P256.agree(device.private, peerPublic)
        override fun biometricEcdh(peerPublics: List<ByteArray>, prompt: String): List<ByteArray> {
            synchronized(prompts) { prompts.add(prompt) }
            if (!allowBiometric) throw KeyException.Denied()
            return peerPublics.map { P256.agree(biometric.private, it) }
        }
    }

    private class Result(val status: Int, val out: String, val err: String)

    private val dir: File = Files.createTempDirectory("mayi").toFile()

    /** Runs the real requester CLI as another machine with its own config. */
    private fun mayi(vararg args: String): Result {
        val process = ProcessBuilder(listOf(System.getenv("MAYI_CLI")) + args).apply {
            environment()["MAYI_CONFIG"] = File(dir, "requester.json").path
            environment()["HOME"] = File(dir, "nohome").path
            environment()["MAYI_SESSION"] = "kotlin-test"
            redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        }.start()
        val out = process.inputStream.bufferedReader().readText()
        val err = process.errorStream.bufferedReader().readText()
        assertTrue(process.waitFor(30, TimeUnit.SECONDS))
        return Result(process.exitValue(), out, err)
    }

    private fun eventually(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out waiting for: $what" }
            Thread.sleep(20)
        }
    }

    private fun phone(keys: TestKeys, name: String = "phone"): Pair<MayiController, UShort> {
        val controller = MayiController(noticeLingerMs = 200)
        controller.open(File(dir, "$name.db").path, name, keys)
        return controller to controller.listen(0u, listOf("127.0.0.1"))
    }

    @Test
    fun keyEncodingsMatchTheCore() {
        val keys = TestKeys()
        assertEquals(65, keys.devicePublic().size)
        // Reopening unwraps the vault key through ECDH done on this side.
        val path = File(dir, "reopen.db").path
        MayiController().apply { open(path, "a", keys); assertNull(saveSecret("L4", 4u, mapOf("value" to "x"), emptyList(), 60u)) }
        val reopened = MayiController().apply { open(path, "a", keys) }
        assertEquals(listOf("L4"), reopened.state.secrets.map { it.name })
        assertTrue(runCatching { MayiController().open(path, "b", TestKeys()) }.isFailure)
    }

    @Test
    fun aPairedMachineIsServedAtEveryLevel() {
        val keys = TestKeys()
        val (controller, _) = phone(keys)
        for (level in 1..4) {
            assertNull(controller.saveSecret("L$level", level.toUByte(), mapOf("value" to "secret-$level"), emptyList(), 600u))
        }
        val token = controller.device!!.startPairing(listOf("127.0.0.1"), 60u)
        assertEquals("Paired with phone as vm.\n", mayi("pair", token, "--name", "vm").out)
        eventually("the machine to be listed") { controller.state.machines.map { it.name } == listOf("vm") }

        // Level 1 from another machine is raised to a notice.
        val one = mayi("run", "-s", "L1", "-r", "kotlin", "--", "sh", "-c", "echo \$L1")
        assertEquals("[masked]\n", one.out)
        eventually("the notice to clear") { controller.state.notices.isEmpty() }
        // The log is reloaded just after the notice goes.
        eventually("the request to be logged") {
            controller.state.log.any { it.event == "request" && it.remote && it.requester.startsWith("vm (") }
        }

        // Level 3 waits for an answer from the screen.
        val answerer = Thread {
            eventually("a prompt") { controller.state.pending.size == 1 }
            val prompt = controller.state.pending[0]
            // The program as the requester found it, by its full path.
            assertEquals("/bin/sh -c 'echo \$L3'", prompt.request.command)
            assertTrue(prompt.request.remote)
            controller.answer(prompt.runId, ApprovalChoice.ONCE)
        }.apply { start() }
        assertEquals("[masked]\n", mayi("run", "-s", "L3", "-r", "kotlin", "--", "sh", "-c", "echo \$L3").out)
        answerer.join()
        assertTrue(controller.state.pending.isEmpty())

        // Level 4 goes through the biometric key.
        keys.allowBiometric = false
        assertEquals(77, mayi("run", "-s", "L4", "-r", "kotlin", "--", "true").status)
        keys.allowBiometric = true
        assertEquals("8\n", mayi("run", "-s", "L4", "-r", "kotlin", "--", "sh", "-c", "echo \${#L4}").out)
        assertTrue(keys.prompts.last().startsWith("Unlock L4 for "))

        // Nobody answers: denied when the requester gives up.
        val ignored = mayi("run", "-s", "L3", "-r", "kotlin", "--timeout", "1", "--", "true")
        assertEquals(75, ignored.status)
        eventually("the prompt to be withdrawn") { controller.state.pending.isEmpty() }

        assertNull(controller.revokeMachine(controller.state.machines[0].id))
        assertFalse(mayi("list").status == 0)
    }

    @Test
    fun aLoginKeepsItsWebsitesAndNeverReachesACommand() {
        val (controller, _) = phone(TestKeys())
        assertNull(
            controller.saveSecret(
                "github", 3u, mapOf("username" to "amine", "password" to "pw", "totp" to "JBSWY3DPEHPK3PXP"),
                emptyList(), 600u, login = true, sites = listOf("https://GitHub.com/login"),
            ),
        )
        val saved = controller.state.secrets.single()
        assertTrue(saved.login)
        assertEquals(listOf("github.com"), saved.sites)
        assertTrue(controller.saveSecret("bad", 3u, mapOf("password" to "pw"), emptyList(), 0u, login = true)!!.contains("website"))

        val token = controller.device!!.startPairing(listOf("127.0.0.1"), 60u)
        mayi("pair", token, "--name", "vm")
        val listed = mayi("list").out
        assertTrue(listed, listed.contains("github\tlevel 3\tpassword,totp,username\tlogin for github.com"))
        val run = mayi("run", "-s", "P=github/password", "-r", "read it", "--", "true")
        assertEquals(77, run.status)
        assertTrue(run.err, run.err.contains("github is a login"))
        assertTrue("refused before any prompt", controller.state.pending.isEmpty())
    }

    @Test
    fun thePhoneAddsANewDeviceThatShowsACode() {
        val phoneKeys = TestKeys()
        val (phone, _) = phone(phoneKeys)
        assertNull(phone.saveSecret("L4", 4u, mapOf("value" to "four"), emptyList(), 60u))

        // What a new Mac's setup window does.
        val join = JoinInvitation.open(listOf("127.0.0.1"), 60u)
        val code = join.token()
        assertTrue(code.startsWith("mayij1."))
        val macKeys = TestKeys()
        val macPath = File(dir, "mac.db").path
        var failure: Throwable? = null
        val waiter = Thread { runCatching { join.wait(macPath, "mac", macKeys) }.onFailure { failure = it } }.apply { start() }

        assertTrue("an invitation is not a code", phone.addDevice("mayid1.AAAA").isFailure)
        assertEquals("mac", phone.addDevice(code).getOrThrow())
        waiter.join(10_000)
        assertNull(failure)
        assertEquals(listOf("Add mac as a device of this vault"), phoneKeys.prompts)
        assertEquals(setOf("mac", "phone"), phone.state.devices.map { it.name }.toSet())

        val mac = MayiController().apply { open(macPath, "mac", macKeys) }
        assertEquals(listOf("L4"), mac.state.secrets.map { it.name })
    }

    @Test
    fun thePhoneManagesTheVaultAsTheMacDoes() {
        val keys = TestKeys()
        val (phone, _) = phone(keys)
        assertTrue("a new vault is empty", phone.vaultIsEmpty)

        // Editing rules keeps the value.
        assertNull(phone.saveSecret("TOKEN", 3u, mapOf("value" to "abc"), emptyList(), 900u))
        assertNull(phone.updateRules("TOKEN", listOf("gh *"), 60u, emptyList()))
        val edited = phone.state.secrets.single()
        assertEquals(listOf("gh *"), edited.allow)
        assertEquals(60uL, edited.maxGrantSecs)
        assertTrue(!phone.vaultIsEmpty)
        assertEquals("only on this phone", 1u, edited.copies)

        // Its owner can see the value; that is logged, without the value.
        assertEquals("abc", phone.reveal("TOKEN").getOrThrow().fields.single().value)
        assertEquals("view", phone.state.log.last().event)

        // Pairing a machine from the phone.
        val token = phone.startPairing(60u).getOrThrow()
        assertEquals("Paired with phone as vm.\n", mayi("pair", token, "--name", "vm").out)
        eventually("the pairing to show") { phone.state.lastPaired == "vm" }

        // Inviting a device from the phone: it scans or pastes the invitation.
        val invitation = phone.startEnrolment(60u).getOrThrow()
        val otherKeys = TestKeys()
        joinVault(File(dir, "other.db").path, "other phone", otherKeys, invitation)
        eventually("the device to show") { phone.state.lastDeviceAdded == "other phone" }
        eventually("a second copy") { phone.state.secrets.single().copies == 2u }

        // A recovery key, and removing a device with the secrets to rotate.
        assertTrue(phone.createRecoveryKey().getOrThrow().startsWith("mayi-recovery1."))
        val other = phone.state.devices.first { it.name == "other phone" }
        assertEquals(listOf("TOKEN"), phone.removeDevice(other.id).getOrThrow())
        assertTrue(phone.state.devices.first { it.name == "other phone" }.removed)
        assertEquals("one copy again", 1u, phone.state.secrets.single().copies)

        // The removed device may still know the value: the secret says so
        // until it is replaced, or its owner dismisses the note.
        val note = phone.state.secrets.single().rotate.single()
        assertEquals("other phone", note.who)
        assertEquals("removed", note.why)
        assertNull(phone.dismissRotation("TOKEN"))
        assertTrue(phone.state.secrets.single().rotate.isEmpty())
    }

    @Test
    fun foldersAreKeptWithTheRules() {
        val (phone, _) = phone(TestKeys())
        assertNull(phone.saveSecret("TOKEN", 3u, mapOf("value" to "abc"), emptyList(), 900u, folder = " Work "))
        assertEquals("Work", phone.state.secrets.single().folder)
        // Changing only the rules moves it, and an empty folder means none.
        assertNull(phone.updateRules("TOKEN", emptyList(), 900u, emptyList(), "Personal"))
        assertEquals("Personal", phone.state.secrets.single().folder)
        assertNull(phone.updateRules("TOKEN", emptyList(), 900u, emptyList(), ""))
        assertNull(phone.state.secrets.single().folder)
        assertEquals("abc", phone.reveal("TOKEN").getOrThrow().fields.single().value)
    }

    @Test
    fun aPhoneJoinsAnotherDevicesVault() {
        val macKeys = TestKeys()
        val (mac, _) = phone(macKeys, "mac")
        assertNull(mac.saveSecret("FROM_MAC", 4u, mapOf("value" to "m"), emptyList(), 60u))
        val token = mac.device!!.startEnrolment(listOf("127.0.0.1"), 60u)

        val phoneKeys = TestKeys()
        joinVault(File(dir, "phone.db").path, "phone", phoneKeys, token)
        assertEquals(listOf("Add phone as a device of this vault"), macKeys.prompts)
        val (phone, _) = phone(phoneKeys)
        assertEquals(listOf("FROM_MAC"), phone.state.secrets.map { it.name })
        assertEquals(listOf("mac", "phone"), phone.state.devices.map { it.name })

        assertNull(phone.saveSecret("FROM_PHONE", 1u, mapOf("value" to "p"), emptyList(), 60u))
        phone.sync()
        assertEquals("mac: up to date", phone.state.syncStatus)
        eventually("the Mac to learn the phone's secret") { mac.state.secrets.any { it.name == "FROM_PHONE" } }
    }

    @Test
    fun twoFactorCodesComeFromTheKeyNotTheScreen() {
        val code = dev.mayi.ffi.twoFactorCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        assertEquals(6, code.code.length)
        assertTrue(code.validSecs in 1uL..30uL)
        assertTrue(runCatching { dev.mayi.ffi.twoFactorCode("not a key!") }.isFailure)
    }
}
