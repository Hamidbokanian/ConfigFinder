package app.configfinder.core;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** The three client apps and which configs each one can actually import. */
public enum AppTarget {
    V2RAY("v2ray (v2rayNG و مشابه)", "com.v2ray.ang"),
    OUTLINE("Outline", "org.outline.android.client"),
    NPV("NPV Tunnel", "com.napsternetlabs.napsternetv");

    public final String displayName;
    public final String launchPackage;

    // Outline only speaks Shadowsocks with AEAD ciphers and has no plugin support.
    private static final Set<String> OUTLINE_CIPHERS = new HashSet<>(Arrays.asList(
            "chacha20-ietf-poly1305", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm"));

    AppTarget(String displayName, String launchPackage) {
        this.displayName = displayName;
        this.launchPackage = launchPackage;
    }

    public boolean accepts(ProxyConfig c) {
        if (this == OUTLINE) {
            return c.protocol.equals("ss") && !c.ssPlugin && OUTLINE_CIPHERS.contains(c.ssMethod);
        }
        return true; // vmess, vless, trojan and ss all import fine in v2ray clients and NPV Tunnel
    }
}
