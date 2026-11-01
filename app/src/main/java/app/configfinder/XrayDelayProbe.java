package app.configfinder;

import android.content.Context;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import app.configfinder.core.RealDelayScanner;

/**
 * Talks to the Xray core (libv2ray.aar, downloaded at build time) through reflection, so the app
 * still compiles and runs, just without real tests, if the core is missing.
 */
final class XrayDelayProbe implements RealDelayScanner.DelayProbe {
    private final Method measure;

    private XrayDelayProbe(Method measure) {
        this.measure = measure;
    }

    /** Returns null when the core is not bundled in this build. */
    static XrayDelayProbe create(Context ctx) {
        try {
            Class<?> k = Class.forName("libv2ray.Libv2ray");
            try {
                Method init = k.getMethod("initCoreEnv", String.class, String.class);
                init.invoke(null, ctx.getFilesDir().getAbsolutePath(), "");
            } catch (Throwable ignored) {
                // older/newer builds may not need it
            }
            Method m = k.getMethod("measureOutboundDelay", String.class, String.class);
            return new XrayDelayProbe(m);
        } catch (Throwable t) {
            return null;
        }
    }

    @Override
    public long measure(String xrayConfigJson, String url) throws Exception {
        try {
            Object r = measure.invoke(null, xrayConfigJson, url);
            return ((Number) r).longValue();
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            throw new Exception(String.valueOf(cause));
        }
    }
}
