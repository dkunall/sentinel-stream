package com.sentinelstream.detection.domain.engine;

import com.sentinelstream.detection.domain.rule.RuleSpec;
import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.NetworkType;

import java.util.List;
import java.util.Optional;

/**
 * Speed implied by two consecutive matching events' locations. City-level GeoIP is only good to a few
 * hundred kilometres, so short hops are ignored, and a jump involving a VPN exit or a mobile carrier
 * (which route users through far-away gateways) is reported as low confidence instead of an incident.
 */
public final class TravelDetector implements Detector {

    static final double MIN_KM = 500;

    @Override
    public Optional<Detection> evaluate(ActiveRule rule, EnrichedEvent e, RuleState st, Profile profile, RuleSet set) {
        RuleSpec.Travel spec = (RuleSpec.Travel) rule.compiled().spec();
        if (!Conditions.matches(spec.step(), e, null, profile) || e.geo() == null) {
            return Optional.empty();
        }
        long now = e.ts().toEpochMilli();
        Optional<Detection> out = Optional.empty();
        if (st.lastMs != null && now >= st.lastMs) {
            double km = Haversine.km(st.lastLat, st.lastLon, e.geo().lat(), e.geo().lon());
            double hours = Math.max((now - st.lastMs) / 3_600_000.0, 1 / 60.0);
            double kmh = km / hours;
            if (km >= MIN_KM && kmh > spec.maxKmh()) {
                NetworkType before = NetworkType.valueOf(st.lastNetwork);
                boolean weak = before.movesUsersAround() || e.network().movesUsersAround();
                out = Optional.of(new Detection(List.of(e.id()), weak ? Confidence.LOW : Confidence.HIGH, String.format(
                        "%s -> %s: %.0f km in %.0f min (%.0f km/h)%s", st.lastCity, e.geo().city(), km,
                        (now - st.lastMs) / 60_000.0, kmh, weak ? "; VPN or mobile network involved" : "")));
            }
        }
        if (st.lastMs == null || now >= st.lastMs) {
            st.lastMs = now;
            st.lastLat = e.geo().lat();
            st.lastLon = e.geo().lon();
            st.lastCity = e.geo().city();
            st.lastNetwork = e.network().name();
        }
        return out;
    }
}
