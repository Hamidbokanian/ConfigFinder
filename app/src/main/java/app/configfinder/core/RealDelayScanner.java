package app.configfinder.core;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Second stage: runs each candidate through a real proxy core and measures the delay of an actual
 * HTTPS request THROUGH the proxy. Only configs that really carry traffic survive.
 * The core itself is injected (DelayProbe) so this logic can be tested without Android.
 */
public final class RealDelayScanner {
    private RealDelayScanner() {}

    public interface DelayProbe {
        /** Returns the delay in ms; throws when the proxy does not work. */
        long measure(String xrayConfigJson, String url) throws Exception;
    }

    public interface Listener {
        void onProgress(int done, int total, int found);
    }

    public static final class Options {
        public String testUrl = "https://www.gstatic.com/generate_204";
        public int maxRealMs = 1500;
        public int wantResults = 8;
        public int maxCandidates = 60;
        public int threads = 6;
        public long deadlineMs = 90_000L;
        public int maxReturned = 20;
    }

    public static List<ProxyConfig> verify(List<ProxyConfig> candidates, final DelayProbe probe, final Options o,
                                           Listener listener, final AtomicBoolean cancel) {
        List<ProxyConfig> list = new ArrayList<>(candidates);
        if (list.size() > o.maxCandidates) list = new ArrayList<>(list.subList(0, o.maxCandidates));
        int total = list.size();
        if (total == 0) return new ArrayList<>();

        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, Math.min(o.threads, total)), r -> {
            Thread t = new Thread(r, "real-delay");
            t.setDaemon(true);
            return t;
        });
        ExecutorCompletionService<ProxyConfig> ecs = new ExecutorCompletionService<>(pool);
        for (final ProxyConfig c : list) {
            ecs.submit((Callable<ProxyConfig>) () -> {
                if (cancel.get()) return null;
                String ip;
                try {
                    ip = InetAddress.getByName(c.host).getHostAddress();
                } catch (Exception e) {
                    return null;
                }
                String json = XrayConfigBuilder.build(c, ip);
                if (json == null) return null; // link type we cannot test: do not offer it
                try {
                    long ms = probe.measure(json, o.testUrl);
                    if (ms > 0 && ms <= o.maxRealMs) {
                        c.realMs = (int) ms;
                        return c;
                    }
                } catch (Exception | LinkageError e) {
                    // proxy does not work
                }
                return null;
            });
        }

        long end = System.currentTimeMillis() + o.deadlineMs;
        int done = 0;
        List<ProxyConfig> good = new ArrayList<>();
        try {
            while (done < total && !cancel.get()) {
                long left = end - System.currentTimeMillis();
                if (left <= 0) break;
                Future<ProxyConfig> f = ecs.poll(Math.min(left, 500L), TimeUnit.MILLISECONDS);
                if (f == null) continue;
                done++;
                try {
                    ProxyConfig ok = f.get();
                    if (ok != null) good.add(ok);
                } catch (ExecutionException ignored) { }
                if (listener != null) listener.onProgress(done, total, good.size());
                if (good.size() >= o.wantResults) break;
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }

        Collections.sort(good, (a, b) -> Integer.compare(a.realMs, b.realMs));
        if (good.size() > o.maxReturned) return new ArrayList<>(good.subList(0, o.maxReturned));
        return good;
    }
}
