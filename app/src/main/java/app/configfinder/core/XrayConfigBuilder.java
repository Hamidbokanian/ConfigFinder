package app.configfinder.core;

import java.util.Locale;
import java.util.Map;

/**
 * Builds a minimal Xray-core JSON (one outbound, no inbound) for a share link, so the core can
 * measure the REAL delay through that proxy. Returns null when the link uses something we cannot
 * express (unsupported transport, missing Reality key, allowInsecure, plugins...).
 *
 * The server address is passed in already resolved, so the core never needs its own DNS for it.
 * SNI / Host headers keep the original names.
 */
public final class XrayConfigBuilder {
    private XrayConfigBuilder() {}

    private static final String[] FINGERPRINTS = {
        "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
        "random", "randomized", "randomizednoalpn", "unsafe"
    };

    /** Minimal config (one outbound, no inbound) used for the real-delay test. */
    public static String build(ProxyConfig c, String address) {
        String outbound = outbound(c, address);
        if (outbound == null) return null;
        return "{\"log\":{\"loglevel\":\"warning\"},\"outbounds\":[" + outbound + "]}";
    }

    /**
     * Full-device VPN config: a TUN inbound (the file descriptor comes from Android's VpnService and
     * is handed to the core separately) plus the proxy outbound. DNS questions from apps are answered
     * by the core's own DNS over HTTPS, sent through the proxy.
     */
    public static String buildVpn(ProxyConfig c, String address, int mtu) {
        String outbound = outbound(c, address);
        if (outbound == null) return null;
        return "{\"log\":{\"loglevel\":\"warning\"},"
                + "\"dns\":{\"servers\":[\"https://1.1.1.1/dns-query\",\"https://8.8.8.8/dns-query\"],\"queryStrategy\":\"UseIPv4\"},"
                + "\"inbounds\":[{\"tag\":\"tun-in\",\"protocol\":\"tun\",\"settings\":{\"name\":\"xray0\",\"mtu\":" + mtu + ",\"userLevel\":0}}],"
                + "\"outbounds\":[" + outbound + ",{\"tag\":\"direct\",\"protocol\":\"freedom\"},{\"tag\":\"dns-out\",\"protocol\":\"dns\"}],"
                + "\"routing\":{\"domainStrategy\":\"AsIs\",\"rules\":["
                + "{\"type\":\"field\",\"inboundTag\":[\"tun-in\"],\"port\":\"53\",\"outboundTag\":\"dns-out\"}]}}";
    }

    private static String outbound(ProxyConfig c, String address) {
        if (c == null || address == null || address.isEmpty()) return null;
        try {
            switch (c.protocol) {
                case "vless": return vless(c, address);
                case "vmess": return vmess(c, address);
                case "trojan": return trojan(c, address);
                case "ss": return shadowsocks(c, address);
                default: return null;
            }
        } catch (RuntimeException e) {
            return null;
        }
    }

    // ---------------------------------------------------------------- vless / trojan

    private static String vless(ProxyConfig c, String address) {
        String[] ui = uriParts(c.raw, "vless");
        if (ui == null || ui[0].isEmpty()) return null;
        Map<String, String> p = ConfigParser.parseQuery(ui[1]);
        String net = normNet(p.get("type"));
        String sec = security(p.get("security"), "none");
        String stream = stream(net, sec, p, c, null);
        if (stream == null) return null;
        String enc = nonEmpty(p.get("encryption"), "none");
        StringBuilder user = new StringBuilder("{\"id\":" + q(ui[0]) + ",\"encryption\":" + q(enc));
        String flow = p.get("flow");
        if (flow != null && !flow.isEmpty() && net.equals("tcp") && !sec.equals("none")) {
            user.append(",\"flow\":").append(q(flow));
        }
        user.append("}");
        return "{\"tag\":\"proxy\",\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":" + q(address)
                + ",\"port\":" + c.port + ",\"users\":[" + user + "]}]},\"streamSettings\":" + stream + "}";
    }

    private static String trojan(ProxyConfig c, String address) {
        String[] ui = uriParts(c.raw, "trojan");
        if (ui == null || ui[0].isEmpty()) return null;
        Map<String, String> p = ConfigParser.parseQuery(ui[1]);
        String net = normNet(p.get("type"));
        String sec = security(p.get("security"), "tls");
        String stream = stream(net, sec, p, c, null);
        if (stream == null) return null;
        return "{\"tag\":\"proxy\",\"protocol\":\"trojan\",\"settings\":{\"servers\":[{\"address\":" + q(address)
                + ",\"port\":" + c.port + ",\"password\":" + q(ui[0]) + "}]},\"streamSettings\":" + stream + "}";
    }

    // ---------------------------------------------------------------- vmess

    private static String vmess(ProxyConfig c, String address) {
        String body = c.raw.substring("vmess://".length());
        int h = body.indexOf('#');
        if (h >= 0) body = body.substring(0, h);
        String json = ConfigParser.decodeBase64(body);
        if (json == null) return null;
        String id = ConfigParser.jsonValue(json, "id");
        if (id == null || id.isEmpty()) return null;
        int aid = 0;
        try {
            String a = ConfigParser.jsonValue(json, "aid");
            if (a != null && !a.isEmpty()) aid = Integer.parseInt(a.trim());
        } catch (NumberFormatException ignored) { }
        String scy = nonEmpty(ConfigParser.jsonValue(json, "scy"), "auto");

        // map the vmess JSON fields onto the same parameter names the URI-style links use
        Map<String, String> p = new java.util.HashMap<>();
        String net = normNet(ConfigParser.jsonValue(json, "net"));
        String type = ConfigParser.jsonValue(json, "type");
        String host = ConfigParser.jsonValue(json, "host");
        String path = ConfigParser.jsonValue(json, "path");
        put(p, "host", host);
        put(p, "path", path);
        put(p, "sni", ConfigParser.jsonValue(json, "sni"));
        put(p, "alpn", ConfigParser.jsonValue(json, "alpn"));
        put(p, "fp", ConfigParser.jsonValue(json, "fp"));
        if (net.equals("grpc")) {
            put(p, "servicename", path);
            put(p, "mode", type);
        } else {
            put(p, "headertype", type);
        }
        String sec = "tls".equalsIgnoreCase(ConfigParser.jsonValue(json, "tls")) ? "tls" : "none";
        String stream = stream(net, sec, p, c, null);
        if (stream == null) return null;
        return "{\"tag\":\"proxy\",\"protocol\":\"vmess\",\"settings\":{\"vnext\":[{\"address\":" + q(address)
                + ",\"port\":" + c.port + ",\"users\":[{\"id\":" + q(id) + ",\"alterId\":" + aid
                + ",\"security\":" + q(scy) + "}]}]},\"streamSettings\":" + stream + "}";
    }

    // ---------------------------------------------------------------- shadowsocks

    private static String shadowsocks(ProxyConfig c, String address) {
        if (c.ssPlugin) return null;
        String[] cred = ConfigParser.ssCredentials(c.raw);
        if (cred == null || cred[1].isEmpty()) return null;
        return "{\"tag\":\"proxy\",\"protocol\":\"shadowsocks\",\"settings\":{\"servers\":[{\"address\":" + q(address)
                + ",\"port\":" + c.port + ",\"method\":" + q(cred[0]) + ",\"password\":" + q(cred[1])
                + "}]},\"streamSettings\":{\"network\":\"tcp\"}}";
    }

    // ---------------------------------------------------------------- stream settings

    private static String stream(String net, String sec, Map<String, String> p, ProxyConfig c, String unused) {
        String hostHeader = nonEmpty(p.get("host"), c.host);
        String path = nonEmpty(p.get("path"), "/");
        StringBuilder sb = new StringBuilder("{\"network\":" + q(net));
        switch (net) {
            case "tcp":
                if ("http".equalsIgnoreCase(p.get("headertype"))) {
                    sb.append(",\"tcpSettings\":{\"header\":{\"type\":\"http\",\"request\":{\"path\":[")
                      .append(q(path)).append("],\"headers\":{\"Host\":[").append(q(hostHeader)).append("]}}}}");
                }
                break;
            case "ws":
                sb.append(",\"wsSettings\":{\"path\":").append(q(path))
                  .append(",\"headers\":{\"Host\":").append(q(hostHeader)).append("}}");
                break;
            case "grpc":
                sb.append(",\"grpcSettings\":{\"serviceName\":").append(q(nonEmpty(p.get("servicename"), "")))
                  .append(",\"multiMode\":").append("multi".equalsIgnoreCase(p.get("mode"))).append("}");
                break;
            case "httpupgrade":
                sb.append(",\"httpupgradeSettings\":{\"path\":").append(q(path))
                  .append(",\"host\":").append(q(hostHeader)).append("}");
                break;
            case "xhttp":
                sb.append(",\"xhttpSettings\":{\"path\":").append(q(path)).append(",\"host\":").append(q(hostHeader))
                  .append(",\"mode\":").append(q(nonEmpty(p.get("mode"), "auto"))).append("}");
                break;
            default:
                return null; // kcp, quic, h2 ... not supported by this tester
        }

        String serverName = nonEmpty(p.get("sni"), nonEmpty(p.get("peer"), nonEmpty(p.get("host"), c.host)));
        String fp = fingerprint(p.get("fp"));
        if (sec.equals("tls")) {
            if (isTrue(p.get("allowinsecure")) || isTrue(p.get("insecure"))) return null; // removed in recent cores
            sb.append(",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":").append(q(serverName))
              .append(",\"fingerprint\":").append(q(fp));
            String alpn = p.get("alpn");
            if (alpn != null && !alpn.isEmpty()) {
                sb.append(",\"alpn\":[");
                String[] parts = alpn.split(",");
                boolean first = true;
                for (String a : parts) {
                    String t = a.trim();
                    if (t.isEmpty()) continue;
                    if (!first) sb.append(',');
                    sb.append(q(t));
                    first = false;
                }
                sb.append("]");
            }
            sb.append("}");
        } else if (sec.equals("reality")) {
            String pbk = p.get("pbk");
            if (pbk == null || pbk.isEmpty()) return null;
            sb.append(",\"security\":\"reality\",\"realitySettings\":{\"serverName\":").append(q(serverName))
              .append(",\"fingerprint\":").append(q(fp))
              .append(",\"publicKey\":").append(q(pbk))
              .append(",\"shortId\":").append(q(nonEmpty(p.get("sid"), "")));
            String spx = p.get("spx");
            if (spx != null && !spx.isEmpty()) sb.append(",\"spiderX\":").append(q(spx));
            sb.append("}");
        } else {
            sb.append(",\"security\":\"none\"");
        }
        sb.append("}");
        return sb.toString();
    }

    // ---------------------------------------------------------------- helpers

    /** {userinfo, query} for scheme://userinfo@host:port?query#name, or null. */
    private static String[] uriParts(String raw, String scheme) {
        String rest = raw.substring(scheme.length() + 3);
        int h = rest.indexOf('#');
        if (h >= 0) rest = rest.substring(0, h);
        String query = "";
        int qi = rest.indexOf('?');
        if (qi >= 0) { query = rest.substring(qi + 1); rest = rest.substring(0, qi); }
        int at = rest.lastIndexOf('@');
        if (at < 0) return null;
        return new String[] { ConfigParser.urlDecode(rest.substring(0, at)), query };
    }

    private static String normNet(String n) {
        if (n == null || n.isEmpty()) return "tcp";
        n = n.toLowerCase(Locale.ROOT);
        if (n.equals("raw")) return "tcp";
        if (n.equals("splithttp")) return "xhttp";
        return n;
    }

    private static String security(String s, String dflt) {
        if (s == null || s.isEmpty()) return dflt;
        s = s.toLowerCase(Locale.ROOT);
        return (s.equals("tls") || s.equals("reality")) ? s : "none";
    }

    private static String fingerprint(String fp) {
        if (fp == null) return "chrome";
        String f = fp.toLowerCase(Locale.ROOT);
        for (String ok : FINGERPRINTS) if (ok.equals(f)) return f;
        return "chrome";
    }

    private static boolean isTrue(String v) {
        return v != null && (v.equals("1") || v.equalsIgnoreCase("true"));
    }

    private static String nonEmpty(String v, String dflt) {
        return (v == null || v.isEmpty()) ? dflt : v;
    }

    private static void put(Map<String, String> m, String k, String v) {
        if (v != null && !v.isEmpty()) m.put(k, v);
    }

    /** JSON string literal. */
    static String q(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.append('"').toString();
    }
}
