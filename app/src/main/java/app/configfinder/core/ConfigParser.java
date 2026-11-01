package app.configfinder.core;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses share links and subscription blobs. Pure Java so it can be unit tested on a normal JVM. */
public final class ConfigParser {
    private ConfigParser() {}

    /** Accepts a plain list of links (one per line) or a base64 encoded list. */
    public static List<ProxyConfig> parseBlob(String text) {
        List<ProxyConfig> out = new ArrayList<>();
        if (text == null) return out;
        String t = text.trim();
        if (t.isEmpty()) return out;
        if (!t.contains("://")) {
            String dec = decodeBase64(t);
            if (dec != null && dec.contains("://")) t = dec;
        }
        for (String line : t.split("[\\r\\n]+")) {
            ProxyConfig c = parseLine(line.trim());
            if (c != null) out.add(c);
        }
        return out;
    }

    public static ProxyConfig parseLine(String line) {
        if (line == null) return null;
        String s = line.trim();
        int sch = s.indexOf("://");
        if (sch <= 0) return null;
        String scheme = s.substring(0, sch).toLowerCase(Locale.ROOT);
        try {
            switch (scheme) {
                case "vmess": return parseVmess(s);
                case "vless":
                case "trojan": return parseUriStyle(scheme, s);
                case "ss": return parseSs(s);
                default: return null;
            }
        } catch (RuntimeException e) {
            return null;
        }
    }

    // ---- vmess://BASE64(json) ----
    private static ProxyConfig parseVmess(String s) {
        String body = s.substring("vmess://".length());
        String name = "";
        int h = body.indexOf('#');
        if (h >= 0) { name = urlDecode(body.substring(h + 1)); body = body.substring(0, h); }
        String json = decodeBase64(body);
        if (json == null) return null;
        String host = jsonValue(json, "add");
        int port = parsePort(jsonValue(json, "port"));
        if (host == null || host.isEmpty() || port < 0) return null;
        String tls = jsonValue(json, "tls");
        String sec = "tls".equalsIgnoreCase(tls) ? "tls" : "none";
        String sni = jsonValue(json, "sni");
        if (sni == null || sni.isEmpty()) sni = jsonValue(json, "host");
        String ps = jsonValue(json, "ps");
        if (name.isEmpty() && ps != null) name = ps;
        return new ProxyConfig("vmess", host.trim(), port, s, name, sec, sni == null ? "" : sni.trim(), "", false);
    }

    // ---- vless:// and trojan://  scheme://user@host:port?params#name ----
    private static ProxyConfig parseUriStyle(String scheme, String s) {
        String rest = s.substring(scheme.length() + 3);
        String name = "";
        int h = rest.indexOf('#');
        if (h >= 0) { name = urlDecode(rest.substring(h + 1)); rest = rest.substring(0, h); }
        String query = "";
        int q = rest.indexOf('?');
        if (q >= 0) { query = rest.substring(q + 1); rest = rest.substring(0, q); }
        int at = rest.lastIndexOf('@');
        if (at < 0) return null;
        String hostPort = rest.substring(at + 1);
        int slash = hostPort.indexOf('/');
        if (slash >= 0) hostPort = hostPort.substring(0, slash);
        String[] hp = splitHostPort(hostPort);
        if (hp == null) return null;
        Map<String, String> params = parseQuery(query);
        String sec = params.get("security");
        if (sec == null || sec.isEmpty()) sec = scheme.equals("trojan") ? "tls" : "none";
        sec = sec.toLowerCase(Locale.ROOT);
        if (!sec.equals("tls") && !sec.equals("reality")) sec = "none";
        String sni = params.get("sni");
        if (sni == null || sni.isEmpty()) sni = params.get("peer");
        return new ProxyConfig(scheme, hp[0], Integer.parseInt(hp[1]), s, name, sec, sni == null ? "" : sni, "", false);
    }

    // ---- ss://BASE64(method:pass)@host:port  |  ss://BASE64(method:pass@host:port) ----
    private static ProxyConfig parseSs(String s) {
        String rest = s.substring("ss://".length());
        String name = "";
        int h = rest.indexOf('#');
        if (h >= 0) { name = urlDecode(rest.substring(h + 1)); rest = rest.substring(0, h); }
        boolean plugin = false;
        int q = rest.indexOf('?');
        if (q >= 0) { plugin = rest.substring(q + 1).contains("plugin="); rest = rest.substring(0, q); }
        String method;
        String hostPort;
        int at = rest.lastIndexOf('@');
        if (at >= 0) {
            String userinfo = urlDecode(rest.substring(0, at));
            hostPort = rest.substring(at + 1);
            String dec = userinfo.contains(":") ? userinfo : decodeBase64(userinfo);
            if (dec == null) return null;
            int c = dec.indexOf(':');
            if (c <= 0) return null;
            method = dec.substring(0, c);
        } else {
            String dec = decodeBase64(rest);
            if (dec == null) return null;
            int at2 = dec.lastIndexOf('@');
            if (at2 < 0) return null;
            String ui = dec.substring(0, at2);
            hostPort = dec.substring(at2 + 1);
            int c = ui.indexOf(':');
            if (c <= 0) return null;
            method = ui.substring(0, c);
        }
        int slash = hostPort.indexOf('/');
        if (slash >= 0) hostPort = hostPort.substring(0, slash);
        String[] hp = splitHostPort(hostPort);
        if (hp == null) return null;
        return new ProxyConfig("ss", hp[0], Integer.parseInt(hp[1]), s, name, "none", "", method, plugin);
    }

    /** Returns {method, password} for an ss:// link, or null. */
    static String[] ssCredentials(String raw) {
        String rest = raw.substring("ss://".length());
        int h = rest.indexOf('#');
        if (h >= 0) rest = rest.substring(0, h);
        int q = rest.indexOf('?');
        if (q >= 0) rest = rest.substring(0, q);
        String cred;
        int at = rest.lastIndexOf('@');
        if (at >= 0) {
            String userinfo = urlDecode(rest.substring(0, at));
            cred = userinfo.contains(":") ? userinfo : decodeBase64(userinfo);
        } else {
            String dec = decodeBase64(rest);
            if (dec == null) return null;
            int at2 = dec.lastIndexOf('@');
            if (at2 < 0) return null;
            cred = dec.substring(0, at2);
        }
        if (cred == null) return null;
        int c = cred.indexOf(':');
        if (c <= 0) return null;
        return new String[] { cred.substring(0, c), cred.substring(c + 1) };
    }

    // ---- helpers ----
    /** Returns {host, port} or null. Handles [ipv6]:port. */
    static String[] splitHostPort(String hp) {
        hp = hp.trim();
        String host;
        String portStr;
        if (hp.startsWith("[")) {
            int end = hp.indexOf(']');
            if (end < 0 || end + 1 >= hp.length() || hp.charAt(end + 1) != ':') return null;
            host = hp.substring(1, end);
            portStr = hp.substring(end + 2);
        } else {
            int c = hp.lastIndexOf(':');
            if (c <= 0) return null;
            host = hp.substring(0, c);
            portStr = hp.substring(c + 1);
        }
        int port = parsePort(portStr);
        if (host.isEmpty() || port < 0) return null;
        return new String[] { host, String.valueOf(port) };
    }

    static int parsePort(String p) {
        if (p == null) return -1;
        try {
            int v = Integer.parseInt(p.trim());
            return (v >= 1 && v <= 65535) ? v : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static Map<String, String> parseQuery(String query) {
        Map<String, String> m = new HashMap<>();
        if (query == null || query.isEmpty()) return m;
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            m.put(part.substring(0, eq).toLowerCase(Locale.ROOT), urlDecode(part.substring(eq + 1)));
        }
        return m;
    }

    /** Tiny JSON value reader: works for "key":"text" and "key":123 without needing org.json. */
    static String jsonValue(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(?:\"([^\"]*)\"|([^,}\\s]+))").matcher(json);
        if (!m.find()) return null;
        return m.group(1) != null ? m.group(1) : m.group(2);
    }

    static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /** Standard and URL-safe base64, with or without padding. Returns null when it is not valid base64. */
    public static String decodeBase64(String in) {
        if (in == null) return null;
        String t = in.replaceAll("\\s+", "").replace('-', '+').replace('_', '/');
        int pad = t.length() % 4;
        if (pad == 1) return null;
        if (pad > 0) t = t + "====".substring(pad);
        try {
            return new String(java.util.Base64.getDecoder().decode(t), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
