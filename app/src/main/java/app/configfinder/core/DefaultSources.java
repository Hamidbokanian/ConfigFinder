package app.configfinder.core;

import java.util.ArrayList;
import java.util.List;

/** Public config lists. "top100"/"tested" lists are already checked with a real proxy test by their maintainers. */
public final class DefaultSources {
    private DefaultSources() {}

    private static final String H = "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/";
    private static final String B = "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/";
    private static final String N = "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/configs/proxy_configs_tested.txt";

    public static List<String> forTarget(AppTarget t) {
        List<String> l = new ArrayList<>();
        l.add(H + "top100.txt");
        l.add(N);
        if (t == AppTarget.OUTLINE) {
            l.add(H + "ss.txt");
            l.add(B + "ss.txt");
        } else {
            l.add(H + "vless.txt");
            l.add(H + "vmess.txt");
            l.add(H + "trojan.txt");
            l.add(H + "ss.txt");
            l.add(B + "vless.txt");
            l.add(B + "vmess.txt");
            l.add(B + "trojan.txt");
            l.add(B + "ss.txt");
        }
        return l;
    }

    public static boolean isTestedSource(String url) {
        String u = url.toLowerCase();
        return u.contains("top100") || u.contains("tested");
    }
}
