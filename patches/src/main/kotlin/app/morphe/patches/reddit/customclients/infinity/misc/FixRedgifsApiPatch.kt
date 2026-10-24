/*
 * Copyright 2026 wchill.
 * https://github.com/wchill/patcheddit
 *
 * See the included NOTICE file for GPLv3 §7(b) and §7(c) terms that apply to this code.
 */

package app.morphe.patches.reddit.customclients.infinity.misc

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.methodCall
import app.morphe.patches.reddit.customclients.fixRedgifsApiPatch
import app.morphe.patches.reddit.customclients.infinity.InfinityCompatible
import app.morphe.patches.reddit.customclients.infinity.misc.extension.sharedExtensionPatch
import app.morphe.util.registersUsed

val fixRedgifsApiPatch = fixRedgifsApiPatch(sharedExtensionPatch) {
    compatibleWith(*InfinityCompatible)

    execute {
        Fingerprint(
            filters = listOf(
                methodCall(
                    definingClass = "Lokhttp3/OkHttpClient\$Builder;",
                    name = "build",
                    returnType = "Lokhttp3/OkHttpClient;"
                )
            ),
            custom = { _, classDef ->
                !classDef.type.startsWith("Lapp/morphe/")
            }
        ).matchAll().forEach { match ->
            val index = match.instructionMatches[0].index
            val instruction = match.instructionMatches[0].instruction
            val builderReg = instruction.registersUsed[0]
            match.method.replaceInstruction(
                index,
                """
                    invoke-static { v$builderReg }, Lapp/morphe/extension/infinity/FixRedgifsApiPatch;->install(Lokhttp3/OkHttpClient${'$'}Builder;)Lokhttp3/OkHttpClient;
                """
            )
        }
    }
}
