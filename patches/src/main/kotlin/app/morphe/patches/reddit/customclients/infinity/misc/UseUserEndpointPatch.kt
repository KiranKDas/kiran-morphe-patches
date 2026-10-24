/*
 * Copyright 2026 wchill.
 * https://github.com/wchill/patcheddit
 *
 * See the included NOTICE file for GPLv3 §7(b) and §7(c) terms that apply to this code.
 */

package app.morphe.patches.reddit.customclients.infinity.misc

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.getInstruction
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patches.all.misc.PatchCategory
import app.morphe.patches.reddit.customclients.infinity.InfinityCompatible
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction

val useUserEndpointPatch = bytecodePatch(
    name = "Use /user/ endpoint",
    description = "Opens user profiles through /user/ instead of the deprecated /u/ endpoint.",
    default = true
) {
    category(PatchCategory.LOGIN)
    compatibleWith(*InfinityCompatible)

    execute {
        Fingerprint(
            strings = listOf("/u/"),
            custom = { _, classDef ->
                !classDef.type.startsWith("Lapp/morphe/")
            }
        ).matchAll().forEach { match ->
            match.stringMatches.forEach { stringMatch ->
                if (stringMatch.string == "/u/") {
                    val reg = match.method.getInstruction<OneRegisterInstruction>(stringMatch.index).registerA
                    match.method.replaceInstruction(
                        stringMatch.index,
                        "const-string v$reg, \"/user/\""
                    )
                }
            }
        }

        Fingerprint(
            strings = listOf("u/%s"),
            custom = { _, classDef ->
                !classDef.type.startsWith("Lapp/morphe/")
            }
        ).matchAll().forEach { match ->
            match.stringMatches.forEach { stringMatch ->
                if (stringMatch.string == "u/%s") {
                    val reg = match.method.getInstruction<OneRegisterInstruction>(stringMatch.index).registerA
                    match.method.replaceInstruction(
                        stringMatch.index,
                        "const-string v$reg, \"user/%s\""
                    )
                }
            }
        }
    }
}
