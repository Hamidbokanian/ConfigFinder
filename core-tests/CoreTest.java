import app.configfinder.core.*;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class CoreTest {
    static int failures = 0;
    static void check(boolean cond, String what) {
        System.out.println((cond ? "PASS  " : "FAIL  ") + what);
        if (!cond) failures++;
    }
    static String b64(String s) { return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)); }

    public static void main(String[] args) throws Exception {
        // --- vless / trojan, taken from real public lists ---
        ProxyConfig v = ConfigParser.parseLine("vless://394f6981-a782-4779-9a85-e6cf22935d93@95.173.199.113:8443?encryption=none&security=tls&sni=ams1.fromblancwithlove.com&type=tcp&headerType=none#Czech-Republic");
        check(v != null && v.protocol.equals("vless") && v.host.equals("95.173.199.113") && v.port == 8443, "vless host/port");
        check(v != null && v.security.equals("tls") && v.sni.equals("ams1.fromblancwithlove.com") && v.name.equals("Czech-Republic"), "vless tls + sni + name");

        ProxyConfig t = ConfigParser.parseLine("trojan://humanity@104.18.12.149:443?security=tls&sni=www.calmlunch.com&type=ws&host=www.calmlunch.com&path=%2Fassignment#OpenProxyList");
        check(t != null && t.protocol.equals("trojan") && t.host.equals("104.18.12.149") && t.port == 443 && t.security.equals("tls"), "trojan parse");

        ProxyConfig t2 = ConfigParser.parseLine("trojan://pw@example.com:443#x");
        check(t2 != null && t2.security.equals("tls") && t2.sni.equals("example.com"), "trojan defaults to tls, sni falls back to host");

        ProxyConfig r = ConfigParser.parseLine("vless://uuid@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=abc&sid=1&type=tcp#R");
        check(r != null && r.security.equals("reality") && r.sni.equals("www.microsoft.com"), "vless reality");

        ProxyConfig v6 = ConfigParser.parseLine("vless://uuid@[2001:db8::1]:8443?security=none#v6");
        check(v6 != null && v6.host.equals("2001:db8::1") && v6.port == 8443, "ipv6 host");

        // --- vmess ---
        String vmessJson = "{\"v\":\"2\",\"ps\":\"my node\",\"add\":\"example.org\",\"port\":\"8080\",\"id\":\"abc\",\"net\":\"ws\",\"tls\":\"tls\",\"sni\":\"cdn.example.org\"}";
        ProxyConfig vm = ConfigParser.parseLine("vmess://" + b64(vmessJson));
        check(vm != null && vm.host.equals("example.org") && vm.port == 8080 && vm.security.equals("tls") && vm.sni.equals("cdn.example.org") && vm.name.equals("my node"), "vmess json");
        ProxyConfig vm2 = ConfigParser.parseLine("vmess://" + b64("{\"add\":\"1.1.1.1\",\"port\":443,\"tls\":\"\"}"));
        check(vm2 != null && vm2.port == 443 && vm2.security.equals("none"), "vmess numeric port, no tls");

        // --- shadowsocks: official Outline example + legacy form + plugin ---
        ProxyConfig s1 = ConfigParser.parseLine("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxl@outline-server.example.com:8388/?outline=1");
        check(s1 != null && s1.host.equals("outline-server.example.com") && s1.port == 8388 && s1.ssMethod.equals("chacha20-ietf-poly1305"), "ss SIP002 (Outline docs example)");
        ProxyConfig s2 = ConfigParser.parseLine("ss://" + b64("aes-256-gcm:pass@9.9.9.9:443") + "#legacy");
        check(s2 != null && s2.host.equals("9.9.9.9") && s2.port == 443 && s2.ssMethod.equals("aes-256-gcm") && s2.name.equals("legacy"), "ss legacy fully-encoded");
        ProxyConfig s3 = ConfigParser.parseLine("ss://" + b64("aes-256-gcm:pass") + "@8.8.8.8:443/?plugin=v2ray-plugin%3Btls#p");
        check(s3 != null && s3.ssPlugin, "ss plugin detected");
        ProxyConfig s4 = ConfigParser.parseLine("ss://" + b64("rc4-md5:pass") + "@7.7.7.7:443#old");
        check(s4 != null && s4.ssMethod.equals("rc4-md5"), "ss old cipher parsed");

        // --- garbage must not crash ---
        check(ConfigParser.parseLine("hello world") == null, "garbage line -> null");
        check(ConfigParser.parseLine("vless://nohost") == null, "broken vless -> null");
        check(ConfigParser.parseLine("vless://u@host:99999?security=tls") == null, "bad port -> null");
        check(ConfigParser.parseLine("vmess://!!!notbase64!!!") == null, "bad vmess -> null");
        check(ConfigParser.parseLine("hysteria2://x@1.1.1.1:443") == null, "unsupported scheme -> null");

        // --- blobs: plain, base64 and mixed line endings ---
        String plain = v.raw + "\r\n" + t.raw + "\n\n" + "junk\n" + s1.raw;
        check(ConfigParser.parseBlob(plain).size() == 3, "plain blob keeps 3 valid of 4 lines");
        check(ConfigParser.parseBlob(b64(plain)).size() == 3, "base64 blob decodes");
        check(ConfigParser.parseBlob("").isEmpty() && ConfigParser.parseBlob(null).isEmpty(), "empty blob");

        // --- app filters ---
        check(AppTarget.OUTLINE.accepts(s1), "Outline accepts ss + AEAD");
        check(!AppTarget.OUTLINE.accepts(s3), "Outline rejects ss with plugin");
        check(!AppTarget.OUTLINE.accepts(s4), "Outline rejects old cipher");
        check(!AppTarget.OUTLINE.accepts(v), "Outline rejects vless");
        check(AppTarget.V2RAY.accepts(v) && AppTarget.NPV.accepts(t) && AppTarget.V2RAY.accepts(vm), "v2ray/NPV accept vless/trojan/vmess");

        // --- latency scanner against local sockets ---
        java.net.ServerSocket open = new java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"));
        int openPort = open.getLocalPort();
        Thread acc = new Thread(() -> { try { while (true) open.accept().close(); } catch (Exception ignored) { } });
        acc.setDaemon(true); acc.start();
        java.net.ServerSocket tmp = new java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
        int closedPort = tmp.getLocalPort(); tmp.close();

        ProxyConfig good = ConfigParser.parseLine("vless://u@127.0.0.1:" + openPort + "?security=none#good");
        ProxyConfig dead = ConfigParser.parseLine("vless://u@127.0.0.1:" + closedPort + "?security=none#dead");
        ProxyConfig tlsOnPlain = ConfigParser.parseLine("vless://u@127.0.0.1:" + openPort + "?security=tls&sni=example.com#tlsfail");
        good.fromTestedSource = false;
        LatencyScanner.Options o = new LatencyScanner.Options();
        List<ProxyConfig> res = LatencyScanner.scan(Arrays.asList(dead, good, tlsOnPlain), o, null, new AtomicBoolean(false));
        check(res.size() == 1 && res.get(0).name.equals("good"), "scanner keeps the live endpoint, drops closed port and failed TLS probe");
        check(res.size() == 1 && res.get(0).pingMs >= 0 && res.get(0).pingMs <= 150, "ping within threshold (" + (res.isEmpty() ? "n/a" : res.get(0).pingMs + "ms") + ")");

        LatencyScanner.Options strict = new LatencyScanner.Options();
        strict.maxPingMs = -1; // nothing can pass
        check(LatencyScanner.scan(Arrays.asList(good), strict, null, new AtomicBoolean(false)).isEmpty(), "threshold really filters");

        AtomicBoolean cancelled = new AtomicBoolean(true);
        check(LatencyScanner.scan(Arrays.asList(good), o, null, cancelled).isEmpty(), "cancel flag stops the scan");

        // --- repository against a local HTTP server (base64 sub + plain list + dead source) ---
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String subB64 = b64(v.raw + "\n" + s1.raw + "\n" + s3.raw);
        srv.createContext("/sub64", ex -> { byte[] b = subB64.getBytes(StandardCharsets.UTF_8); ex.sendResponseHeaders(200, b.length); ex.getResponseBody().write(b); ex.close(); });
        srv.createContext("/top100", ex -> { byte[] b = (s1.raw + "\n").getBytes(StandardCharsets.UTF_8); ex.sendResponseHeaders(200, b.length); ex.getResponseBody().write(b); ex.close(); });
        srv.start();
        String base = "http://127.0.0.1:" + srv.getAddress().getPort();
        ConfigRepository.LoadResult lr = ConfigRepository.load(AppTarget.OUTLINE, Arrays.asList(base + "/sub64", base + "/top100", base + "/missing"));
        check(lr.okSources == 2 && lr.totalSources == 3, "dead source skipped (" + lr.okSources + "/" + lr.totalSources + ")");
        check(lr.configs.size() == 1 && lr.configs.get(0).fromTestedSource, "Outline list: filtered, deduped, tested flag merged");
        ConfigRepository.LoadResult lr2 = ConfigRepository.load(AppTarget.V2RAY, Arrays.asList(base + "/sub64"));
        check(lr2.configs.size() == 3, "v2ray list keeps vless + both ss");
        srv.stop(0);

        // --- sources sanity ---
        check(DefaultSources.forTarget(AppTarget.OUTLINE).size() == 4 && DefaultSources.forTarget(AppTarget.NPV).size() == 10, "default source lists");
        check(DefaultSources.isTestedSource(DefaultSources.forTarget(AppTarget.V2RAY).get(0)), "top100 flagged as tested");

        System.out.println(failures == 0 ? "\nALL TESTS PASSED" : "\n" + failures + " TEST(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
