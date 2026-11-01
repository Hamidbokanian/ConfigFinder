package app.configfinder.core;

import java.util.Locale;

/** One proxy config (vmess / vless / trojan / ss) with the data we need to test it. */
public final class ProxyConfig {
    public final String protocol;   // vmess, vless, trojan, ss
    public final String host;
    public final int port;
    public final String raw;        // the original share link, exactly as found
    public final String name;
    public final String security;   // none, tls, reality
    public final String sni;        // never empty (falls back to host)
    public final String ssMethod;   // lower-case cipher for ss, otherwise ""
    public final boolean ssPlugin;  // ss with a plugin (Outline cannot use these)

    public boolean fromTestedSource;
    public int pingMs = -1;      // TCP connect time from this device
    public int realMs = -1;      // real delay through the proxy core (-1 = not measured)
    public boolean tlsChecked;
    public boolean tlsOk;

    public ProxyConfig(String protocol, String host, int port, String raw, String name,
                       String security, String sni, String ssMethod, boolean ssPlugin) {
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        this.raw = raw;
        this.name = name == null ? "" : name;
        this.security = security == null ? "none" : security;
        this.sni = (sni == null || sni.isEmpty()) ? host : sni;
        this.ssMethod = ssMethod == null ? "" : ssMethod.toLowerCase(Locale.ROOT);
        this.ssPlugin = ssPlugin;
    }

    /** Same link without the #name part, used to drop duplicates. */
    public String dedupeKey() {
        int h = raw.indexOf('#');
        return h < 0 ? raw : raw.substring(0, h);
    }
}
