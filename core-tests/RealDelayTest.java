import app.configfinder.core.*;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.*;

public class RealDelayTest {
    static int failures = 0;
    static void check(boolean cond, String what) {
        System.out.println((cond ? "PASS  " : "FAIL  ") + what);
        if (!cond) failures++;
    }
    static String b64(String s) { return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)); }
    static String build(String link) {
        ProxyConfig c = ConfigParser.parseLine(link);
        return c == null ? null : XrayConfigBuilder.build(c, "203.0.113.7");
    }

    public static void main(String[] args) throws Exception {
        List<String> dump = new ArrayList<>();
        Map<String, String> good = new LinkedHashMap<>();
        good.put("vless tcp tls", "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&sni=sni.example.com&type=tcp&fp=chrome&alpn=h2,http/1.1#a");
        good.put("vless reality vision", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?encryption=none&security=reality&sni=www.microsoft.com&fp=firefox&pbk=PUBKEY123&sid=ab12&flow=xtls-rprx-vision&type=tcp#r");
        good.put("vless ws tls", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fmy%20path%3Fed%3D2048#w");
        good.put("vless grpc tls", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&sni=g.example.com&type=grpc&serviceName=svc&mode=multi#g");
        good.put("vless httpupgrade", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:80?security=none&type=httpupgrade&host=h.example.com&path=%2Fu#h");
        good.put("trojan ws tls", "trojan://pa%24%24word@104.18.12.149:443?security=tls&sni=www.calmlunch.com&type=ws&host=www.calmlunch.com&path=%2Fassignment#t");
        good.put("trojan default tls", "trojan://pw@example.com:443#t2");
        good.put("vmess ws tls", "vmess://" + b64("{\"v\":\"2\",\"ps\":\"x\",\"add\":\"example.org\",\"port\":\"443\",\"id\":\"11111111-2222-3333-4444-555555555555\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"ws.example.org\",\"path\":\"/ray\",\"tls\":\"tls\",\"sni\":\"ws.example.org\"}"));
        good.put("vmess grpc", "vmess://" + b64("{\"add\":\"1.1.1.1\",\"port\":443,\"id\":\"11111111-2222-3333-4444-555555555555\",\"net\":\"grpc\",\"path\":\"svcname\",\"type\":\"multi\",\"tls\":\"tls\"}"));
        good.put("ss aead", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxl@outline-server.example.com:8388/?outline=1");
        good.put("ss legacy", "ss://" + b64("aes-256-gcm:p\"ass@9.9.9.9:443") + "#legacy");

        for (Map.Entry<String, String> e : good.entrySet()) {
            String j = build(e.getValue());
            check(j != null, "builds: " + e.getKey());
            if (j != null) dump.add(e.getKey() + "\t" + j);
        }

        Map<String, String> bad = new LinkedHashMap<>();
        bad.put("allowInsecure tls", "vless://u@1.2.3.4:443?security=tls&allowInsecure=1&type=tcp#x");
        bad.put("kcp transport", "vless://u@1.2.3.4:443?security=none&type=kcp#x");
        bad.put("reality without key", "vless://u@1.2.3.4:443?security=reality&sni=a.com&type=tcp#x");
        bad.put("ss with plugin", "ss://" + b64("aes-256-gcm:pw") + "@8.8.8.8:443/?plugin=v2ray-plugin%3Btls#p");
        bad.put("vmess without id", "vmess://" + b64("{\"add\":\"1.1.1.1\",\"port\":443}"));
        for (Map.Entry<String, String> e : bad.entrySet()) {
            check(build(e.getValue()) == null, "rejects: " + e.getKey());
        }
        check(XrayConfigBuilder.build(null, "1.1.1.1") == null && XrayConfigBuilder.build(ConfigParser.parseLine(good.get("trojan default tls")), "") == null, "null-safe");

        try (PrintWriter w = new PrintWriter("/tmp/xray_cfgs.tsv", "UTF-8")) { for (String d : dump) w.println(d); }

        // --- RealDelayScanner with a fake core ---
        // ports encode the scenario: 1001 fast, 1002 slow-but-ok, 1003 throws, 1004 over the limit, 1005 unsupported (kcp)
        ProxyConfig c1 = ConfigParser.parseLine("vless://u@127.0.0.1:1001?security=none&type=tcp#fast");
        ProxyConfig c2 = ConfigParser.parseLine("vless://u@127.0.0.1:1002?security=none&type=tcp#slow");
        ProxyConfig c3 = ConfigParser.parseLine("vless://u@127.0.0.1:1003?security=none&type=tcp#dead");
        ProxyConfig c4 = ConfigParser.parseLine("vless://u@127.0.0.1:1004?security=none&type=tcp#toolong");
        ProxyConfig c5 = ConfigParser.parseLine("vless://u@127.0.0.1:1005?security=none&type=kcp#unsupported");
        final List<String> seenUrls = Collections.synchronizedList(new ArrayList<>());
        RealDelayScanner.DelayProbe fake = (json, url) -> {
            seenUrls.add(url);
            Matcher m = Pattern.compile("\"port\":(\\d+)").matcher(json);
            if (!m.find()) throw new Exception("no port");
            switch (Integer.parseInt(m.group(1))) {
                case 1001: return 120;
                case 1002: return 900;
                case 1003: throw new Exception("connection refused");
                case 1004: return 5000;
                default: return 1;
            }
        };
        RealDelayScanner.Options o = new RealDelayScanner.Options();
        o.wantResults = 99;
        List<ProxyConfig> res = RealDelayScanner.verify(Arrays.asList(c2, c3, c4, c5, c1), fake, o, null, new AtomicBoolean(false));
        check(res.size() == 2, "only configs that really carry traffic survive (got " + res.size() + ")");
        check(res.size() == 2 && res.get(0).name.equals("fast") && res.get(0).realMs == 120 && res.get(1).name.equals("slow"), "sorted by real delay, real delay stored");
        check(!seenUrls.isEmpty() && seenUrls.get(0).equals("https://www.gstatic.com/generate_204"), "default test URL");
        check(!res.contains(c5), "unsupported transport never offered");

        RealDelayScanner.Options strict = new RealDelayScanner.Options();
        strict.maxRealMs = 150; strict.wantResults = 99;
        check(RealDelayScanner.verify(Arrays.asList(c1, c2), fake, strict, null, new AtomicBoolean(false)).size() == 1, "max real delay is enforced");

        RealDelayScanner.Options early = new RealDelayScanner.Options();
        early.wantResults = 1; early.threads = 1;
        List<ProxyConfig> r3 = RealDelayScanner.verify(Arrays.asList(c1, c2), fake, early, null, new AtomicBoolean(false));
        check(r3.size() >= 1, "stops early once enough found");

        check(RealDelayScanner.verify(Arrays.asList(c1), fake, o, null, new AtomicBoolean(true)).isEmpty(), "cancel works");
        check(RealDelayScanner.verify(new ArrayList<>(), fake, o, null, new AtomicBoolean(false)).isEmpty(), "empty input");

        RealDelayScanner.DelayProbe broken = (json, url) -> { throw new NoClassDefFoundError("libv2ray"); };
        check(RealDelayScanner.verify(Arrays.asList(c1), broken, o, null, new AtomicBoolean(false)).isEmpty(), "missing core never crashes the scan");

        // --- VPN (TUN) config ---
        ProxyConfig vc = ConfigParser.parseLine(good.get("vless reality vision"));
        String vpn = XrayConfigBuilder.buildVpn(vc, "203.0.113.7", 1400);
        check(vpn != null && vpn.contains("\"protocol\":\"tun\"") && vpn.contains("\"mtu\":1400") && vpn.contains("\"tag\":\"proxy\""), "VPN config has tun inbound and proxy outbound");
        check(XrayConfigBuilder.buildVpn(ConfigParser.parseLine(bad.get("kcp transport")), "1.2.3.4", 1400) == null, "VPN config rejects unsupported links");
        try (PrintWriter w = new PrintWriter("/tmp/vpn_cfg.json", "UTF-8")) { w.print(vpn); }

        System.out.println(failures == 0 ? "\nALL REAL-DELAY TESTS PASSED" : "\n" + failures + " TEST(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
