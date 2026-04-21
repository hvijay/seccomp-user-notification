package com.example.seccomp.shared;

import android.os.ParcelFileDescriptor;

interface ISeccompPolicyDaemon {
    boolean registerSession(
            String sessionId,
            in ParcelFileDescriptor listenerFd,
            String description,
            int targetPid);
    void unregisterSession(String sessionId);
    void publishPendingRequest(
            String sessionId,
            long notificationId,
            int pid,
            int syscallNr,
            long ioctlCmd);
    int getDecision(String sessionId, long notificationId);
}
