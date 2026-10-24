/*
 * Copyright 2026 wchill.
 * https://github.com/wchill/patcheddit
 *
 * See the included NOTICE file for GPLv3 §7(b) and §7(c) terms that apply to this code.
 */

package app.morphe.patches.reddit.customclients.infinity.misc

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructionsWithLabels
import app.morphe.patcher.extensions.InstructionExtensions.getInstruction
import app.morphe.patcher.util.smali.ExternalLabel
import app.morphe.patches.reddit.customclients.fixSLinksPatch
import app.morphe.patches.reddit.customclients.infinity.InfinityCompatible
import app.morphe.patches.reddit.customclients.infinity.misc.extension.sharedExtensionPatch

val fixSLinksPatch = fixSLinksPatch(sharedExtensionPatch) {
    compatibleWith(*InfinityCompatible)

    execute {
        Fingerprint(
            definingClass = "Lml/docilealligator/infinityforreddit/activities/LinkResolverActivity;",
            name = "onCreate"
        ).methodOrNull?.apply {
            addInstructionsWithLabels(
                0,
                """
                    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
                    move-result-object v0
                    if-eqz v0, :cond_slink_skip
                    invoke-virtual {v0}, Landroid/content/Intent;->getDataString()Ljava/lang/String;
                    move-result-object v0
                    if-eqz v0, :cond_slink_skip
                    invoke-static {v0}, Lapp/morphe/extension/infinity/FixSLinksPatch;->patchResolveSLink(Ljava/lang/String;)Z
                    move-result v0
                    if-eqz v0, :cond_slink_skip
                    invoke-virtual {p0}, Landroid/app/Activity;->finish()V
                    return-void
                """,
                ExternalLabel("cond_slink_skip", getInstruction(0))
            )
        }
    }
}
