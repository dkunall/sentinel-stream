package com.sentinelstream.event;

/** What kind of network an address belongs to, as far as the (coarse) IP table knows. */
public enum NetworkType {
    RESIDENTIAL, MOBILE, CORPORATE, HOSTING, VPN, PRIVATE, UNKNOWN;

    /** VPN exits and carrier NAT move users around, so location jumps from these are weak evidence. */
    public boolean movesUsersAround() {
        return this == VPN || this == MOBILE;
    }
}
