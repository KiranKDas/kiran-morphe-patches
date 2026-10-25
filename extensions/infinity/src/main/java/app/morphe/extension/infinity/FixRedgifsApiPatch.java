/*
 * Copyright 2026 wchill.
 * https://github.com/wchill/patcheddit
 *
 * See the included NOTICE file for GPLv3 §7(b) and §7(c) terms that apply to this code.
 */

package app.morphe.extension.infinity;

import app.morphe.extension.shared.Logger;
import app.morphe.extension.shared.fixes.redgifs.BaseFixRedgifsApiPatch;
import app.morphe.extension.shared.fixes.redgifs.RedgifsTokenManager;
import okhttp3.OkHttpClient;

/**
 * @noinspection unused
 */
public class FixRedgifsApiPatch extends BaseFixRedgifsApiPatch {
    static {
        INSTANCE = new FixRedgifsApiPatch();
    }

    @Override
    public String getDefaultUserAgent() {
        return APIUtils.getUserAgent();
    }

    public static OkHttpClient install(OkHttpClient.Builder builder) {
        return builder.addInterceptor(INSTANCE).build();
    }

    public static String getFreshRedgifsToken() {
        try {
            return RedgifsTokenManager.refreshToken(APIUtils.getUserAgent()).getAccessToken();
        } catch (Throwable t) {
            Logger.printException(() -> "Failed to refresh Redgifs token", t);
            return "";
        }
    }
}
