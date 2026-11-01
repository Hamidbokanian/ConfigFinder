package app.configfinder.core;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Measures TCP connect latency from THIS device (so it reflects the user's own network) and,
 * for TLS/Reality configs, checks that a TLS handshake completes. It does not send any proxy traffic.
 */
public final class LatencyScanner {
    private LatencyScanner() {}

    public interface Listener {
        void onProgress(int done, int total, int found);
    }

    public static final class Options {
        public int maxPingMs = 150;
        public int wantResults = 10;
        public int maxCandidates = 600;
        public int threads = 48;
        public int connectTimeoutMs = 400;
        public int rounds = 3;
        public long deadlineMs = 45_000L;
        public boolean tlsProbe = true;
        public int tlsTimeoutMs = 2500;
        public int maxReturned = 30;
    }

    private static final class Probe {
        final int pingMs;
        final boolean tlsChecked;
        final boolean tlsOk;
        Probe(int p, boolean c, boolean ok) { pingMs = p; tlsChecked = c; tlsOk = ok; }
    }

    private static final Probe FAIL = new Probe(-1, false, false);

    private static final class GroupResult {
        final String key;
        final Probe probe;
        GroupResult(String k, Probe p) { key = k; probe = p; }
    }

    public static List<ProxyConfig> scan(List<ProxyConfig> candidates, final Options o,
                                         Listener listener, final AtomicBoolean cancel) {
        List<ProxyConfig> tested = new ArrayList<>();
        List<ProxyConfig> rest = new ArrayList<>();
        for (ProxyConfig c : candidates) (c.fromTestedSource ? tested : rest).add(c);
        Collections.shuffle(rest);
        List<ProxyConfig> ordered = new ArrayList<>(tested);
        ordered.addAll(rest);
        if (ordered.size() > o.maxCandidates) ordered = new ArrayList<>(ordered.subList(0, o.maxCandidates));

        // Many links share one server: probe each endpoint once.
        final Map<String, List<ProxyConfig>> groups = new LinkedHashMap<>();
        for (ProxyConfig c : ordered) {
            List<ProxyConfig> g = groups.get(probeKey(c));
            if (g == null) { g = new ArrayList<>(); groups.put(probeKey(c), g); }
            g.add(c);
        }

        int total = groups.size();
        if (total == 0) return new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, Math.min(o.threads, total)), r -> {
            Thread t = new Thread(r, "probe");
            t.setDaemon(true);
            return t;
        });
        ExecutorCompletionService<GroupResult> ecs = new ExecutorCompletionService<>(pool);
        for (Map.Entry<String, List<ProxyConfig>> e : groups.entrySet()) {
            final String key = e.getKey();
            final ProxyConfig rep = e.getValue().get(0);
            ecs.submit(() -> new GroupResult(key, probe(rep, o, cancel)));
        }

        long end = System.currentTimeMillis() + o.deadlineMs;
        int done = 0;
        int found = 0;
        List<ProxyConfig> good = new ArrayList<>();
        try {
            while (done < total && !cancel.get()) {
                long left = end - System.currentTimeMillis();
                if (left <= 0) break;
                Future<GroupResult> f = ecs.poll(Math.min(left, 500L), TimeUnit.MILLISECONDS);
                if (f == null) continue;
                done++;
                GroupResult gr;
                try {
                    gr = f.get();
                } catch (ExecutionException ex) {
                    continue;
                }
                Probe p = gr.probe;
                if (p.pingMs >= 0 && p.pingMs <= o.maxPingMs) {
                    for (ProxyConfig c : groups.get(gr.key)) {
                        c.pingMs = p.pingMs;
                        c.tlsChecked = p.tlsChecked;
                        c.tlsOk = p.tlsOk;
                        good.add(c);
                    }
                    found++;
                }
                if (listener != null) listener.onProgress(done, total, found);
                if (found >= o.wantResults) break;
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }

        // configs pre-checked by their maintainers first, then lowest ping
        Collections.sort(good, (a, b) -> {
            if (a.fromTestedSource != b.fromTestedSource) return a.fromTestedSource ? -1 : 1;
            return Integer.compare(a.pingMs, b.pingMs);
        });
        if (good.size() > o.maxReturned) return new ArrayList<>(good.subList(0, o.maxReturned));
        return good;
    }

    private static String probeKey(ProxyConfig c) {
        return c.host.toLowerCase() + ":" + c.port + "|" + c.security + "|" + c.sni.toLowerCase();
    }

    private static Probe probe(ProxyConfig c, Options o, AtomicBoolean cancel) {
        InetAddress addr;
        try {
            addr = InetAddress.getByName(c.host);
        } catch (Exception e) {
            return FAIL;
        }
        int[] samples = new int[o.rounds];
        int ok = 0;
        for (int i = 0; i < o.rounds; i++) {
            if (cancel.get()) return FAIL;
            long t0 = System.nanoTime();
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress(addr, c.port), o.connectTimeoutMs);
                samples[ok++] = (int) ((System.nanoTime() - t0) / 1_000_000L);
            } catch (IOException e) {
                if (i == 0) return FAIL; // port closed or too slow: stop early
            } finally {
                try { s.close(); } catch (IOException ignored) { }
            }
        }
        if (ok < (o.rounds / 2) + 1) return FAIL;
        Arrays.sort(samples, 0, ok);
        int median = samples[ok / 2];

        boolean needTls = o.tlsProbe && (c.security.equals("tls") || c.security.equals("reality"));
        if (needTls) {
            if (!tlsHandshake(addr, c, o.tlsTimeoutMs)) return FAIL;
            return new Probe(median, true, true);
        }
        return new Probe(median, false, false);
    }

    private static final TrustManager[] TRUST_ALL = new TrustManager[] {
        new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) { }
            public void checkServerTrusted(X509Certificate[] chain, String authType) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }
    };

    /**
     * Handshake only. Certificates are not validated on purpose: proxy servers (and Reality) often
     * present a certificate that does not match the SNI, and we only want to know the server answers.
     * No user data is sent.
     */
    private static boolean tlsHandshake(InetAddress addr, ProxyConfig c, int timeoutMs) {
        Socket raw = new Socket();
        try {
            raw.connect(new InetSocketAddress(addr, c.port), timeoutMs);
            raw.setSoTimeout(timeoutMs);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, TRUST_ALL, null);
            SSLSocket ss = (SSLSocket) ctx.getSocketFactory().createSocket(raw, c.sni, c.port, true);
            try {
                try {
                    SSLParameters p = ss.getSSLParameters();
                    p.setServerNames(Collections.singletonList(new SNIHostName(c.sni)));
                    ss.setSSLParameters(p);
                } catch (IllegalArgumentException ignored) {
                    // SNI was an IP address: continue without it
                }
                ss.startHandshake();
                return true;
            } finally {
                try { ss.close(); } catch (IOException ignored) { }
            }
        } catch (Exception e) {
            return false;
        } finally {
            try { raw.close(); } catch (IOException ignored) { }
        }
    }
}
