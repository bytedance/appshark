package net.bytedance.security.app.sanitizer.testdata;


public class PendingIntentMutable {
    void f1() {
        PendingIntent.getActivity();

        PendingIntent.getActivity(null, 0, new Intent(), 0);
        PendingIntent.getActivity(null, 0, null, 67108864);
    }

    void f2() {
        PendingIntent.getService(null, 0, new Intent(), 0);
    }

    void f3() {
        PendingIntent.getProvider(null, 0, new Intent(), 0);
        PendingIntent.getProvider(null, 0, new Intent(), 67108864);
    }

    void f4() {
        PendingIntent.getBroadcast(null, 0, new Intent(), 67108864);
    }

    static class PendingIntent {
        static public PendingIntent getActivity(Object ctx, int requestCode, Intent intent, int flags) {
            return new PendingIntent();
        }

        static public PendingIntent getActivity() {
            return new PendingIntent();
        }

        static public PendingIntent getProvider(Object ctx, int requestCode, Intent intent, int flags) {
            return new PendingIntent();
        }

        static public PendingIntent getService(Object ctx, int requestCode, Intent intent, int flags) {
            return new PendingIntent();
        }

        static public PendingIntent getBroadcast(Object ctx, int requestCode, Intent intent, int flags) {
            return new PendingIntent();
        }

    }

    static class Intent {

    }
}

