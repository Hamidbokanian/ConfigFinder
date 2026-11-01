package app.configfinder;

import android.content.Context;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Controls the Xray core (libv2ray.aar) through reflection, so the project still compiles even
 * when the AAR is not present. create() returns null in that case.
 */
final class XrayCore {
    private final Object controller;
    private final Method startLoop;
    private final Method stopLoop;
    private final Method measureDelay;

    private XrayCore(Object controller, Method startLoop, Method stopLoop, Method measureDelay) {
        this.controller = controller;
        this.startLoop = startLoop;
        this.stopLoop = stopLoop;
        this.measureDelay = measureDelay;
    }

    static XrayCore create(Context ctx) {
        try {
            Class<?> lib = Class.forName("libv2ray.Libv2ray");
            try {
                lib.getMethod("initCoreEnv", String.class, String.class)
                        .invoke(null, ctx.getFilesDir().getAbsolutePath(), "");
            } catch (Throwable ignored) {
                // optional
            }
            Class<?> callbackType = Class.forName("libv2ray.CoreCallbackHandler");
            // The core only wants to be told about lifecycle events; we have nothing to do for them.
            InvocationHandler noop = (proxy, method, args) -> {
                Class<?> rt = method.getReturnType();
                if (rt == long.class) return 0L;
                if (rt == int.class) return 0;
                if (rt == boolean.class) return false;
                return null;
            };
            Object handler = Proxy.newProxyInstance(callbackType.getClassLoader(), new Class<?>[] { callbackType }, noop);
            Object controller = lib.getMethod("newCoreController", callbackType).invoke(null, handler);
            Class<?> cc = controller.getClass();
            return new XrayCore(controller,
                    cc.getMethod("startLoop", String.class, int.class),
                    cc.getMethod("stopLoop"),
                    cc.getMethod("measureDelay", String.class));
        } catch (Throwable t) {
            return null;
        }
    }

    /** Starts the core on the given TUN file descriptor. Throws when the config is rejected. */
    void start(String configJson, int tunFd) throws Exception {
        call(startLoop, configJson, tunFd);
    }

    void stop() {
        try {
            call(stopLoop);
        } catch (Throwable ignored) {
            // already stopped
        }
    }

    /** Real delay (ms) of an HTTPS request through the running proxy, or throws. */
    long measure(String url) throws Exception {
        Object r = call(measureDelay, url);
        return ((Number) r).longValue();
    }

    private Object call(Method m, Object... args) throws Exception {
        try {
            return m.invoke(controller, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            throw new Exception(String.valueOf(cause));
        }
    }
}
