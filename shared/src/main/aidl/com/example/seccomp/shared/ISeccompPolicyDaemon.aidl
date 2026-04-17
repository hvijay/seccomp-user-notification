package com.example.seccomp.shared;

import android.os.ParcelFileDescriptor;

interface ISeccompPolicyDaemon {
    boolean registerSession(String sessionId, in ParcelFileDescriptor listenerFd, String description);
    void unregisterSession(String sessionId);
}
