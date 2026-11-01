package app.configfinder;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

import app.configfinder.core.AppTarget;
import app.configfinder.core.ConfigRepository;
import app.configfinder.core.DefaultSources;
import app.configfinder.core.LatencyScanner;
import app.configfinder.core.ProxyConfig;
import app.configfinder.core.RealDelayScanner;

public class MainActivity extends Activity {

    private static final String PREFS = "config_finder";
    private static final int BG = Color.parseColor("#0F172A");
    private static final int CARD = Color.parseColor("#1E293B");
    private static final int TEXT_MAIN = Color.parseColor("#F1F5F9");
    private static final int TEXT_DIM = Color.parseColor("#94A3B8");
    private static final int BLUE = Color.parseColor("#2563EB");
    private static final int GREEN = Color.parseColor("#16A34A");
    private static final int PURPLE = Color.parseColor("#7C3AED");
    private static final int SLATE = Color.parseColor("#334155");

    private static final String CREATOR_PHONE = "09378976737";
    private static final int REQ_VPN = 10;
    private static final int REQ_NOTIF = 11;

    private TextView vpnStatus;
    private Button disconnectBtn;
    private boolean autoConnect = false;
    private int autoTries = 0;
    private BroadcastReceiver vpnReceiver;

    private TextView statusView;
    private TextView resultView;
    private ProgressBar progress;
    private LinearLayout resultBox;
    private final List<Button> targetButtons = new ArrayList<>();

    private AtomicBoolean cancel = new AtomicBoolean(false);
    private AppTarget currentTarget;
    private final List<ProxyConfig> results = new ArrayList<>();
    private int index = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        registerVpnReceiver();
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] { "android.permission.POST_NOTIFICATIONS" }, REQ_NOTIF);
        }
        if (ProxyVpnService.STATE_CONNECTED.equals(ProxyVpnService.currentState())) {
            updateVpnUi(ProxyVpnService.STATE_CONNECTED, "VPN فعاله", 0);
        }
    }

    @Override
    protected void onDestroy() {
        cancel.set(true);
        if (vpnReceiver != null) {
            try { unregisterReceiver(vpnReceiver); } catch (Exception ignored) { }
        }
        super.onDestroy();
    }

    // ------------------------------------------------------------------ UI

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        root.setPadding(dp(20), dp(40), dp(20), dp(28));
        scroll.addView(root, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = text("استخراج کانفیگ پرسرعت", 26, TEXT_MAIN, true);
        root.addView(title);

        TextView sub = text("کانفیگ تست‌شده‌ی واقعی، مخصوص هر برنامه. تست از اینترنت خودت انجام میشه.", 14, TEXT_DIM, false);
        sub.setPadding(0, dp(6), 0, dp(14));
        root.addView(sub);

        TextView warn = text("⚠️ قبل از اسکن، VPN رو خاموش کن؛ وگرنه پینگ‌ها واقعی نیستن.", 13, Color.parseColor("#FBBF24"), false);
        warn.setPadding(0, 0, 0, dp(8));
        root.addView(warn);

        vpnStatus = text("", 15, Color.parseColor("#4ADE80"), true);
        vpnStatus.setPadding(0, dp(4), 0, dp(4));
        vpnStatus.setVisibility(View.GONE);
        root.addView(vpnStatus);

        disconnectBtn = makeButton("قطع اتصال VPN", Color.parseColor("#DC2626"));
        disconnectBtn.setVisibility(View.GONE);
        disconnectBtn.setOnClickListener(v -> disconnectVpn());
        root.addView(disconnectBtn);

        Button auto = makeButton("اتصال خودکار با VPN (بهترین کانفیگ)", Color.parseColor("#0891B2"));
        auto.setOnClickListener(v -> { autoConnect = true; autoTries = 0; startScan(AppTarget.V2RAY); });
        targetButtons.add(auto);
        root.addView(auto);

        addTargetButton(root, "کانفیگ برای v2ray", AppTarget.V2RAY, BLUE);
        addTargetButton(root, "کانفیگ برای Outline", AppTarget.OUTLINE, GREEN);
        addTargetButton(root, "کانفیگ برای NPV Tunnel", AppTarget.NPV, PURPLE);

        progress = new ProgressBar(this);
        progress.setIndeterminate(true);
        progress.setVisibility(View.GONE);
        LinearLayout.LayoutParams plp = new LinearLayout.LayoutParams(dp(36), dp(36));
        plp.gravity = Gravity.CENTER_HORIZONTAL;
        plp.topMargin = dp(16);
        root.addView(progress, plp);

        statusView = text("", 14, TEXT_MAIN, false);
        statusView.setPadding(0, dp(12), 0, dp(4));
        root.addView(statusView);

        resultBox = new LinearLayout(this);
        resultBox.setOrientation(LinearLayout.VERTICAL);
        resultBox.setPadding(dp(16), dp(16), dp(16), dp(16));
        GradientDrawable cardBg = new GradientDrawable();
        cardBg.setColor(CARD);
        cardBg.setCornerRadius(dp(16));
        resultBox.setBackground(cardBg);
        resultBox.setVisibility(View.GONE);

        resultView = text("", 15, TEXT_MAIN, false);
        resultView.setTextIsSelectable(true);
        resultBox.addView(resultView);

        Button connect = makeButton("اتصال با VPN خود برنامه", Color.parseColor("#0891B2"));
        connect.setOnClickListener(v -> { autoConnect = false; connectCurrent(); });
        resultBox.addView(connect);

        Button copyOpen = makeButton("کپی و باز کردن برنامه", BLUE);
        copyOpen.setOnClickListener(v -> copyAndOpen());
        resultBox.addView(copyOpen);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        Button copy = makeButton("فقط کپی", SLATE);
        copy.setOnClickListener(v -> { copyCurrent(); toast("کپی شد"); });
        Button next = makeButton("بعدی", SLATE);
        next.setOnClickListener(v -> nextResult());
        LinearLayout.LayoutParams copyLp = new LinearLayout.LayoutParams(0, dp(54), 1f);
        copyLp.topMargin = dp(10);
        copyLp.setMarginEnd(dp(8));
        LinearLayout.LayoutParams nextLp = new LinearLayout.LayoutParams(0, dp(54), 1f);
        nextLp.topMargin = dp(10);
        row.addView(copy, copyLp);
        row.addView(next, nextLp);
        resultBox.addView(row);

        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rlp.topMargin = dp(10);
        root.addView(resultBox, rlp);

        TextView note = text("مرحله ۱ پینگ اتصال رو از گوشی تو می‌گیره، مرحله ۲ با هسته‌ی Xray یه درخواست واقعی از داخل کانفیگ می‌فرسته. فقط کانفیگ‌هایی که واقعاً ترافیک رد کردن نشون داده میشن.", 12, TEXT_DIM, false);
        note.setPadding(0, dp(18), 0, dp(6));
        root.addView(note);

        Button settings = makeButton("تنظیمات", SLATE);
        settings.setOnClickListener(v -> showSettings());
        root.addView(settings);

        // creator credit; tapping it opens the dialer with the number filled in
        TextView credit = text("ساخته‌شده توسط حمید بوکانیان\nتماس: " + CREATOR_PHONE, 13, TEXT_DIM, false);
        credit.setGravity(Gravity.CENTER);
        credit.setPadding(0, dp(22), 0, dp(4));
        credit.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Intent.ACTION_DIAL, android.net.Uri.parse("tel:" + CREATOR_PHONE)));
            } catch (Exception ignored) { }
        });
        root.addView(credit);

        setContentView(scroll);
    }

    private void addTargetButton(LinearLayout root, String label, final AppTarget target, int color) {
        Button b = makeButton(label, color);
        b.setOnClickListener(v -> { autoConnect = false; startScan(target); });
        targetButtons.add(b);
        root.addView(b);
    }

    private TextView text(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private Button makeButton(String label, int color) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextColor(Color.WHITE);
        b.setTextSize(16);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(color);
        bg.setCornerRadius(dp(14));
        b.setBackground(bg);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(54));
        lp.topMargin = dp(10);
        b.setLayoutParams(lp);
        return b;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    // ------------------------------------------------------------------ scan

    private void startScan(final AppTarget target) {
        cancel.set(true); // stop any previous scan
        final AtomicBoolean myCancel = new AtomicBoolean(false);
        cancel = myCancel;
        currentTarget = target;
        results.clear();
        index = 0;
        resultBox.setVisibility(View.GONE);
        progress.setVisibility(View.VISIBLE);
        setButtonsEnabled(false);

        final SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
        final int maxPing = sp.getInt("maxPing", 150);
        final int maxReal = sp.getInt("maxReal", 1500);
        final String extra = sp.getString("extra", "");
        final boolean vpn = isVpnActive();

        new Thread(() -> {
            try {
                if (vpn) postStatus(myCancel, "VPN روشنه؛ پینگ‌ها دقیق نیستن. بهتره خاموشش کنی.\nدر حال دریافت لیست…");
                else postStatus(myCancel, "در حال دریافت لیست کانفیگ‌ها…");

                List<String> urls = new ArrayList<>(DefaultSources.forTarget(target));
                for (String line : extra.split("[\\r\\n]+")) {
                    String u = line.trim();
                    if (u.startsWith("http://") || u.startsWith("https://")) urls.add(u);
                }
                ConfigRepository.LoadResult lr = ConfigRepository.load(target, urls);
                if (myCancel.get()) return;
                if (lr.configs.isEmpty()) {
                    endScan(myCancel, "لیستی دریافت نشد (" + lr.okSources + " از " + lr.totalSources
                            + " منبع در دسترس بود). اینترنت رو چک کن یا در «تنظیمات» منبع دیگه‌ای اضافه کن.", null);
                    return;
                }

                postStatus(myCancel, "مرحله ۱: تست اتصال روی " + lr.configs.size() + " کانفیگ…");
                LatencyScanner.Options o = new LatencyScanner.Options();
                o.maxPingMs = maxPing;
                o.wantResults = 40;
                o.maxCandidates = 800;
                o.maxReturned = 120;
                List<ProxyConfig> reachable = LatencyScanner.scan(lr.configs, o,
                        (done, total, ok) -> postStatus(myCancel, "مرحله ۱: " + done + " از " + total + "   |   جواب‌دهنده: " + ok),
                        myCancel);
                if (myCancel.get()) return;
                if (reachable.isEmpty()) {
                    endScan(myCancel, "هیچ سروری با پینگ اتصال زیر " + maxPing + " میلی‌ثانیه جواب نداد. VPN رو خاموش کن و دوباره بزن؛ یا در «تنظیمات» سقف پینگ رو بالاتر ببر.", null);
                    return;
                }

                XrayDelayProbe probe = XrayDelayProbe.create(getApplicationContext());
                if (probe == null) {
                    endScan(myCancel, "⚠️ هسته‌ی تست واقعی داخل این نسخه نیست؛ فقط پینگ اتصال نشون داده میشه و ممکنه کانفیگ‌ها وصل نشن.\n"
                            + reachable.size() + " کانفیگ پیدا شد.", reachable);
                    return;
                }

                postStatus(myCancel, "مرحله ۲: تست واقعی روی " + Math.min(reachable.size(), 60) + " کانفیگ…");
                RealDelayScanner.Options ro = new RealDelayScanner.Options();
                ro.maxRealMs = maxReal;
                List<ProxyConfig> verified = RealDelayScanner.verify(reachable, probe, ro,
                        (done, total, ok) -> postStatus(myCancel, "مرحله ۲ (تست واقعی): " + done + " از " + total + "   |   کارکرده: " + ok),
                        myCancel);
                if (myCancel.get()) return;
                if (verified.isEmpty()) {
                    endScan(myCancel, "هیچ کانفیگی تست واقعی رو پاس نکرد (زیر " + maxReal + " میلی‌ثانیه). یه بار دیگه بزن یا «حداکثر پینگ واقعی» رو در تنظیمات بالاتر ببر.", null);
                } else {
                    endScan(myCancel, "✔ " + verified.size() + " کانفیگ واقعاً کار کرد.", verified);
                }
            } catch (Exception e) {
                endScan(myCancel, "خطا: " + e.getClass().getSimpleName(), null);
            }
        }, "scan").start();
    }

    private void postStatus(final AtomicBoolean token, final String msg) {
        runOnUiThread(() -> {
            if (token == cancel && !token.get()) statusView.setText(msg);
        });
    }

    private void endScan(final AtomicBoolean token, final String msg, final List<ProxyConfig> found) {
        runOnUiThread(() -> {
            if (token != cancel) return;
            progress.setVisibility(View.GONE);
            setButtonsEnabled(true);
            statusView.setText(msg);
            if (found != null && !found.isEmpty()) {
                results.clear();
                results.addAll(found);
                index = 0;
                showCurrent();
                if (autoConnect) connectCurrent();
            } else {
                autoConnect = false;
            }
        });
    }

    private void setButtonsEnabled(boolean enabled) {
        for (Button b : targetButtons) b.setEnabled(enabled);
    }

    private boolean isVpnActive() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            Network n = cm.getActiveNetwork();
            if (n == null) return false;
            NetworkCapabilities nc = cm.getNetworkCapabilities(n);
            return nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ results

    private void showCurrent() {
        if (results.isEmpty()) return;
        ProxyConfig c = results.get(index);
        StringBuilder sb = new StringBuilder();
        if (c.realMs > 0) {
            sb.append("✔ تست واقعی: ").append(c.realMs).append(" ms   |   ").append(c.protocol.toUpperCase(Locale.ROOT)).append("\n");
            sb.append("پینگ اتصال: ").append(c.pingMs).append(" ms\n");
        } else {
            sb.append("پینگ اتصال: ").append(c.pingMs).append(" ms (تست واقعی انجام نشد)   |   ").append(c.protocol.toUpperCase(Locale.ROOT)).append("\n");
        }
        sb.append(c.host).append(":").append(c.port).append("\n");
        if (c.fromTestedSource) sb.append("از لیست تست‌شده‌ی منبع\n");
        sb.append("\n").append(shorten(c.raw, 110)).append("\n\n");
        sb.append("(").append(index + 1).append(" از ").append(results.size()).append(")");
        resultView.setText(sb.toString());
        resultBox.setVisibility(View.VISIBLE);
    }

    private static String shorten(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private void nextResult() {
        if (results.isEmpty()) return;
        index = (index + 1) % results.size();
        showCurrent();
    }

    private void copyCurrent() {
        if (results.isEmpty()) return;
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("config", results.get(index).raw));
    }

    private void copyAndOpen() {
        if (results.isEmpty() || currentTarget == null) return;
        copyCurrent();
        Intent launch = getPackageManager().getLaunchIntentForPackage(currentTarget.launchPackage);
        if (launch == null) {
            toast("کپی شد؛ ولی " + currentTarget.displayName + " نصب نیست.");
            return;
        }
        toast("کپی شد؛ داخل برنامه «Import from clipboard» رو بزن.");
        startActivity(launch);
    }

    // ------------------------------------------------------------------ VPN

    private void connectCurrent() {
        if (results.isEmpty()) return;
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN); // Android's own "allow VPN" dialog
        } else {
            startVpnService();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                startVpnService();
            } else {
                autoConnect = false;
                toast("اجازه‌ی VPN داده نشد");
            }
        }
    }

    private void startVpnService() {
        if (results.isEmpty()) return;
        Intent i = new Intent(this, ProxyVpnService.class);
        i.setAction(ProxyVpnService.ACTION_START);
        i.putExtra(ProxyVpnService.EXTRA_LINK, results.get(index).raw);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i);
        else startService(i);
    }

    private void disconnectVpn() {
        autoConnect = false;
        Intent i = new Intent(this, ProxyVpnService.class);
        i.setAction(ProxyVpnService.ACTION_STOP);
        startService(i);
    }

    private void registerVpnReceiver() {
        vpnReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context ctx, Intent i) {
                String st = i.getStringExtra(ProxyVpnService.EXTRA_STATE);
                String msg = i.getStringExtra(ProxyVpnService.EXTRA_MSG);
                long delay = i.getLongExtra(ProxyVpnService.EXTRA_DELAY, 0);
                updateVpnUi(st, msg == null ? "" : msg, delay);
                // automatic mode: if this config does not really carry traffic, try the next one
                if (ProxyVpnService.STATE_FAILED.equals(st) && autoConnect
                        && results.size() > 1 && autoTries < 4) {
                    autoTries++;
                    index = (index + 1) % results.size();
                    showCurrent();
                    startVpnService();
                }
            }
        };
        IntentFilter f = new IntentFilter(ProxyVpnService.ACTION_STATE);
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(vpnReceiver, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(vpnReceiver, f);
    }

    private void updateVpnUi(String state, String msg, long delay) {
        if (ProxyVpnService.STATE_CONNECTED.equals(state)) {
            vpnStatus.setTextColor(Color.parseColor("#4ADE80"));
            vpnStatus.setText("🔒 متصل شدی   |   پینگ واقعی: " + delay + " ms\n" + msg);
            vpnStatus.setVisibility(View.VISIBLE);
            disconnectBtn.setVisibility(View.VISIBLE);
        } else if (ProxyVpnService.STATE_CONNECTING.equals(state)) {
            vpnStatus.setTextColor(Color.parseColor("#FBBF24"));
            vpnStatus.setText("⏳ " + msg);
            vpnStatus.setVisibility(View.VISIBLE);
            disconnectBtn.setVisibility(View.VISIBLE);
        } else if (ProxyVpnService.STATE_FAILED.equals(state)) {
            vpnStatus.setTextColor(Color.parseColor("#F87171"));
            vpnStatus.setText("✖ " + msg);
            vpnStatus.setVisibility(View.VISIBLE);
            disconnectBtn.setVisibility(View.GONE);
        } else {
            vpnStatus.setVisibility(View.GONE);
            disconnectBtn.setVisibility(View.GONE);
        }
    }

    // ------------------------------------------------------------------ settings

    private void showSettings() {
        final SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        box.setPadding(dp(20), dp(12), dp(20), 0);

        TextView t1 = new TextView(this);
        t1.setText("حداکثر پینگ (میلی‌ثانیه)");
        box.addView(t1);
        final EditText ping = new EditText(this);
        ping.setInputType(InputType.TYPE_CLASS_NUMBER);
        ping.setText(String.valueOf(sp.getInt("maxPing", 150)));
        box.addView(ping);

        TextView t3 = new TextView(this);
        t3.setText("حداکثر پینگ واقعی (میلی‌ثانیه)");
        t3.setPadding(0, dp(12), 0, 0);
        box.addView(t3);
        final EditText real = new EditText(this);
        real.setInputType(InputType.TYPE_CLASS_NUMBER);
        real.setText(String.valueOf(sp.getInt("maxReal", 1500)));
        box.addView(real);

        TextView t2 = new TextView(this);
        t2.setText("منابع اضافه (هر خط یک لینک لیست کانفیگ)");
        t2.setPadding(0, dp(12), 0, 0);
        box.addView(t2);
        final EditText src = new EditText(this);
        src.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_VARIATION_URI);
        src.setMinLines(3);
        src.setGravity(Gravity.TOP);
        src.setText(sp.getString("extra", ""));
        box.addView(src);

        new AlertDialog.Builder(this)
                .setTitle("تنظیمات")
                .setView(box)
                .setPositiveButton("ذخیره", (d, w) -> {
                    int p = 150;
                    try {
                        p = Integer.parseInt(ping.getText().toString().trim());
                    } catch (NumberFormatException ignored) { }
                    p = Math.max(20, Math.min(1000, p));
                    int r = 1500;
                    try {
                        r = Integer.parseInt(real.getText().toString().trim());
                    } catch (NumberFormatException ignored) { }
                    r = Math.max(100, Math.min(10000, r));
                    sp.edit().putInt("maxPing", p).putInt("maxReal", r)
                            .putString("extra", src.getText().toString()).apply();
                    toast("ذخیره شد");
                })
                .setNegativeButton("لغو", null)
                .show();
    }
}
