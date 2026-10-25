/*
 * Copyright 2026 wchill.
 * https://github.com/wchill/patcheddit
 *
 * See the included NOTICE file for GPLv3 §7(b) and §7(c) terms that apply to this code.
 */

package app.morphe.patches.reddit.customclients.infinity.misc

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patches.reddit.customclients.fixRedgifsApiPatch
import app.morphe.patches.reddit.customclients.infinity.InfinityCompatible
import app.morphe.patches.reddit.customclients.infinity.misc.extension.sharedExtensionPatch
import app.morphe.util.getReference
import app.morphe.util.indexOfFirstInstructionOrThrow
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

private const val EXTENSION_CLASS_DESCRIPTOR = "Lapp/morphe/extension/infinity/FixRedgifsApiPatch;"

val fixRedgifsApiPatch = fixRedgifsApiPatch(sharedExtensionPatch) {
    compatibleWith(*InfinityCompatible)

    execute {
        // 1. Hook the Redgifs token getter method to return a fresh token directly
        Fingerprint(
            strings = listOf("https://api.redgifs.com", "redgifs_access_token"),
            returnType = "Ljava/lang/String;",
            parameters = listOf(),
            custom = { _, classDef -> !classDef.type.startsWith("Lapp/morphe/") }
        ).methodOrNull?.apply {
            addInstructions(
                0,
                """
                    invoke-static { }, $EXTENSION_CLASS_DESCRIPTOR->getFreshRedgifsToken()Ljava/lang/String;
                    move-result-object v0
                    return-object v0
                """
            )
        }

        // 2. Hook the Redgifs interceptor to fetch the fresh token instead of relying on stale SharedPreferences
        Fingerprint(
            strings = listOf("Authorization", "redgifs_access_token"),
            custom = { _, classDef -> !classDef.type.startsWith("Lapp/morphe/") }
        ).methodOrNull?.apply {
            val getStringIndex = indexOfFirstInstructionOrThrow {
                val reference = getReference<MethodReference>()
                reference?.name == "getString" && reference.definingClass == "Landroid/content/SharedPreferences;"
            }
            replaceInstruction(
                getStringIndex,
                """
                    invoke-static { }, $EXTENSION_CLASS_DESCRIPTOR->getFreshRedgifsToken()Ljava/lang/String;
                """
            )
        }
    }
}
