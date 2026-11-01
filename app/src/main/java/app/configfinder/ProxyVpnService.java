package app.configfinder;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.net.InetAddress;

import app.configfinder.core.ConfigParser;
import app.configfinder.core.ProxyConfig;
import app.configfinder.core.XrayConfigBuilder;

/**
 * Turns the whole phone's traffic into the chosen proxy: Android's VpnService creates the TUN
 * device, the Xray core (running inside this app) reads it directly. This app itself is excluded
 * from the tunnel, so the core's own connections go out normally and cannot loop.
 */
public class ProxyVpnService extends VpnService {
    public static final String ACTION_START = "app.configfinder.START";
    public static final String ACTION_STOP = "app.configfinder.STOP";
    public static final String ACTION_STATE = "app.configfinder.STATE";
    public static final String EXTRA_LINK = "link";
    public static final String EXTRA_STATE = "state";
    public static final String EXTRA_MSG = "msg";
    public static final String EXTRA_DELAY = "delay";

    public static final String STATE_CONNECTING = "connecting";
    public static final String STATE_CONNECTED = "connected";
    public static final String STATE_FAILED = "failed";
    public static final String STATE_DISCONNECTED = "disconnected";

    private static final String TEST_URL = "https://www.gstatic.com/generate_204";
    private static final int MTU = 1400;
    private static final String CHANNEL_ID = "vpn";

    private static volatile String currentState = STATE_DISCONNECTED;

    public static String currentState() {
        return currentState;
    }

    private final Object lock = new Object();
    private ParcelFileDescriptor tun;
    private XrayCore core;
    private volatile int generation = 0;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            generation++;
            teardown();
            publish(STATE_DISCONNECTED, "", 0);
            stopForegroundCompat();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action)) {
            final String link = intent.getStringExtra(EXTRA_LINK);
            startForegroundSafe();
            final int myGen = ++generation;
            new Thread(() -> connect(link, myGen), "vpn-connect").start();
            return START_NOT_STICKY;
        }
        return START_NOT_STICKY;
    }

    private void connect(String link, int myGen) {
        publish(STATE_CONNECTING, "در حال اتصال…", 0);
        teardown(); // a previous connection must be gone before the next one starts

        ProxyConfig c = link == null ? null : ConfigParser.parseLine(link);
        if (c == null) { fail("لینک کانفیگ نامعتبره.", myGen); return; }

        String ip;
        try {
            // resolve now, while there is no tunnel yet; the core then dials this IP directly
            ip = InetAddress.getByName(c.host).getHostAddress();
        } catch (Exception e) {
            fail("آدرس سرور پیدا نشد.", myGen);
            return;
        }
        String json = XrayConfigBuilder.buildVpn(c, ip, MTU);
        if (json == null) { fail("این نوع کانفیگ پشتیبانی نمیشه.", myGen); return; }

        XrayCore xc = XrayCore.create(getApplicationContext());
        if (xc == null) { fail("هسته‌ی Xray داخل این نسخه نیست.", myGen); return; }

        int fd;
        synchronized (lock) {
            if (myGen != generation) return;
            Builder b = new Builder();
            b.setSession("Config Finder");
            b.setMtu(MTU);
            b.addAddress("172.19.0.1", 30);
            b.addRoute("0.0.0.0", 0);
            b.addDnsServer("1.1.1.1");
            b.addDnsServer("8.8.8.8");
            try {
                b.addDisallowedApplication(getPackageName()); // keeps the core's own traffic outside the tunnel
            } catch (Exception ignored) { }
            try {
                tun = b.establish();
            } catch (Exception e) {
                tun = null;
            }
            if (tun == null) { fail("اجازه‌ی VPN داده نشد.", myGen); return; }
            try {
                // the core gets its own copy of the descriptor and owns it from now on
                ParcelFileDescriptor dup = tun.dup();
                fd = dup.detachFd();
            } catch (Exception e) {
                fail("ساخت تونل ناموفق بود.", myGen);
                return;
            }
            core = xc;
        }

        try {
            xc.start(json, fd);
        } catch (Throwable t) {
            fail("هسته اجرا نشد.", myGen);
            return;
        }

        long ms = -1;
        for (int attempt = 0; attempt < 2 && ms <= 0; attempt++) {
            if (myGen != generation) return;
            try {
                ms = xc.measure(TEST_URL);
            } catch (Throwable t) {
                ms = -1;
            }
        }
        if (myGen != generation) return;
        if (ms <= 0) {
            fail("وصل شد ولی ترافیک رد نمیشه؛ کانفیگ بعدی رو امتحان کن.", myGen);
            return;
        }
        publish(STATE_CONNECTED, c.protocol.toUpperCase() + "  " + c.host, ms);
    }

    private void fail(String msg, int myGen) {
        if (myGen != generation) return;
        teardown();
        publish(STATE_FAILED, msg, 0);
        stopForegroundCompat();
        stopSelf();
    }

    private void teardown() {
        synchronized (lock) {
            if (core != null) {
                core.stop();
                core = null;
            }
            if (tun != null) {
                try { tun.close(); } catch (Exception ignored) { }
                tun = null;
            }
        }
    }

    private void publish(String state, String msg, long delay) {
        currentState = state;
        Intent i = new Intent(ACTION_STATE);
        i.setPackage(getPackageName());
        i.putExtra(EXTRA_STATE, state);
        i.putExtra(EXTRA_MSG, msg);
        i.putExtra(EXTRA_DELAY, delay);
        sendBroadcast(i);
    }

    @Override
    public void onRevoke() {
        // the user turned the VPN off from Android settings, or another VPN took over
        generation++;
        teardown();
        publish(STATE_DISCONNECTED, "", 0);
        stopForegroundCompat();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        generation++;
        teardown();
        if (!STATE_FAILED.equals(currentState)) currentState = STATE_DISCONNECTED;
        super.onDestroy();
    }

    // ------------------------------------------------------------ notification

    private void startForegroundSafe() {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            nm.createNotificationChannel(new NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW));
            Intent open = new Intent(this, MainActivity.class);
            PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);
            Notification n = new Notification.Builder(this, CHANNEL_ID)
                    .setContentTitle("Config Finder")
                    .setContentText("VPN فعاله")
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentIntent(pi)
                    .setOngoing(true)
                    .build();
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(1, n);
            }
        } catch (Throwable ignored) {
            // the VPN still works as a normal service if the system refuses the notification
        }
    }

    private void stopForegroundCompat() {
        try {
            stopForeground(true);
        } catch (Throwable ignored) { }
    }
}
