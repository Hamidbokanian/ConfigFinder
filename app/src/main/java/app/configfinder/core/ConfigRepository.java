package app.configfinder.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Downloads the source lists in parallel, parses them and keeps only what the chosen app can import. */
public final class ConfigRepository {
    private ConfigRepository() {}

    private static final int MAX_BYTES = 6 * 1024 * 1024;

    public static final class LoadResult {
        public final List<ProxyConfig> configs;
        public final int okSources;
        public final int totalSources;

        LoadResult(List<ProxyConfig> configs, int ok, int total) {
            this.configs = configs;
            this.okSources = ok;
            this.totalSources = total;
        }
    }

    public static LoadResult load(AppTarget target, List<String> urls) {
        int n = Math.max(1, Math.min(6, urls.size()));
        ExecutorService pool = Executors.newFixedThreadPool(n, r -> {
            Thread t = new Thread(r, "fetch");
            t.setDaemon(true);
            return t;
        });
        List<Future<List<ProxyConfig>>> futures = new ArrayList<>();
        for (final String u : urls) {
            final boolean tested = DefaultSources.isTestedSource(u);
            futures.add(pool.submit(() -> {
                List<ProxyConfig> list = ConfigParser.parseBlob(fetch(u));
                for (ProxyConfig c : list) c.fromTestedSource = tested;
                return list;
            }));
        }
        Map<String, ProxyConfig> uniq = new LinkedHashMap<>();
        int ok = 0;
        for (Future<List<ProxyConfig>> f : futures) {
            try {
                List<ProxyConfig> list = f.get(40, TimeUnit.SECONDS);
                ok++;
                for (ProxyConfig c : list) {
                    if (!target.accepts(c)) continue;
                    String key = c.dedupeKey();
                    ProxyConfig prev = uniq.get(key);
                    if (prev == null) uniq.put(key, c);
                    else if (c.fromTestedSource) prev.fromTestedSource = true;
                }
            } catch (Exception e) {
                // a dead source must not stop the others
            }
        }
        pool.shutdownNow();
        return new LoadResult(new ArrayList<>(uniq.values()), ok, urls.size());
    }

    static String fetch(String urlStr) throws IOException {
        HttpURLConnection c = (HttpURLConnection) java.net.URI.create(urlStr).toURL().openConnection();
        c.setConnectTimeout(8000);
        c.setReadTimeout(15000);
        c.setInstanceFollowRedirects(true);
        c.setRequestProperty("User-Agent", "ConfigFinder/1.0");
        try (InputStream in = c.getInputStream()) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int total = 0;
            int r;
            while ((r = in.read(buf)) > 0) {
                total += r;
                if (total > MAX_BYTES) break;
                bos.write(buf, 0, r);
            }
            return bos.toString("UTF-8");
        } finally {
            c.disconnect();
        }
    }
}
