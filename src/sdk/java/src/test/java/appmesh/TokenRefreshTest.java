package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Pacing tests for the token auto-refresh loop — no daemon needed.
 *
 * <p>These encode the reason the pacing exists: the poll interval is a cap on how long the loop
 * sleeps, never a renewal cadence, so a long-lived token must not be renewed once per poll.
 */
public class TokenRefreshTest {

    /** Build an unsigned JWT carrying iat/exp, which is all the pacing logic reads. */
    private static String makeJwt(long iat, long exp) {
        JSONObject claims = new JSONObject().put("exp", exp);
        if (iat > 0) {
            claims.put("iat", iat);
        }
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(claims.toString().getBytes(StandardCharsets.UTF_8));
        return "hdr." + payload + ".sig";
    }

    private static AppMeshClient newClient() {
        return new AppMeshClient(new AppMeshClient.Builder().disableSSLVerify());
    }

    private static long now() {
        return System.currentTimeMillis() / 1000;
    }

    @Test
    void marginIsAFractionOfLifetime() {
        long now = now();
        // 40% of the lifetime, jittered by +/-10% of that margin.
        assertMarginWithin(now, 30 * 60, 648, 792); // 30 minutes -> 10m48s .. 13m12s
        assertMarginWithin(now, 7 * 24 * 3600, 217728, 266112); // 7 days -> 60.48h .. 73.92h
        // A 1 minute token is floored at the 30s offset (40% would be 24s), then clamped to
        // half its life, so it lands in 27s..30s rather than 27s..33s.
        assertMarginWithin(now, 60, 27, 30);
    }

    private static void assertMarginWithin(long now, long lifetime, double min, double max) {
        long exp = now + lifetime;
        double margin = AppMeshClient.refreshMargin(makeJwt(now, exp), exp, now);
        assertTrue(margin >= min && margin <= max,
                "lifetime " + lifetime + "s: margin " + margin + " outside [" + min + ", " + max + "]");
    }

    @Test
    void marginIsStableForTheSameToken() {
        long now = now();
        long exp = now + 3600;
        String token = makeJwt(now, exp);
        double first = AppMeshClient.refreshMargin(token, exp, now);
        for (int i = 0; i < 10; i++) {
            assertEquals(first, AppMeshClient.refreshMargin(token, exp, now), 0.0,
                    "jitter must be deterministic for a given token");
        }
    }

    @Test
    void marginDiffersAcrossTokens() {
        long now = now();
        long exp = now + 3600;
        Set<Double> seen = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            // Same lifetime, different token bytes: the jitter must spread the renewals so a
            // fleet restarted together does not stampede the daemon.
            seen.add(AppMeshClient.refreshMargin(makeJwt(now, exp) + i, exp, now));
        }
        assertTrue(seen.size() >= 5, "expected jitter to spread renewals, got " + seen.size() + " distinct margins");
    }

    @Test
    void marginNeverExceedsHalfTheLifetime() {
        long now = now();
        for (long lifetime : new long[] { 5, 30, 60, 120 }) {
            long exp = now + lifetime;
            double margin = AppMeshClient.refreshMargin(makeJwt(now, exp), exp, now);
            assertTrue(margin <= lifetime / 2.0,
                    "lifetime " + lifetime + "s: margin " + margin + " exceeds half-life");
        }
    }

    /** The regression this rework exists for: a long-lived token renewed once per poll. */
    @Test
    void planDoesNotRenewOncePerPoll() {
        long now = now();
        AppMeshClient client = newClient();
        client.setToken(makeJwt(now, now + 30 * 60));

        AppMeshClient.RefreshPlan plan = client.computeRefreshPlan();
        assertFalse(plan.due, "a token with 30 minutes left must not be due for renewal");
        assertEquals(300, plan.delaySeconds, "expected a poll-capped sleep");
    }

    @Test
    void planRenewsAtTheRefreshPoint() {
        long now = now();
        AppMeshClient client = newClient();
        // Lifetime 30m, already 25m old: past the ~18m refresh point.
        client.setToken(makeJwt(now - 25 * 60, now + 5 * 60));

        AppMeshClient.RefreshPlan plan = client.computeRefreshPlan();
        assertTrue(plan.due, "a token past its refresh point must be due");
        assertEquals(1, plan.delaySeconds, "expected an immediate renewal");
    }

    @Test
    void planWithoutAnyCredentialOnlyPolls() {
        AppMeshClient.RefreshPlan plan = newClient().computeRefreshPlan();
        assertFalse(plan.due, "no credential means nothing to renew");
        assertEquals(300, plan.delaySeconds);
    }

    /** An access token lost to an expired cookie is recoverable — but only if the loop tries. */
    @Test
    void planRenewsFromRefreshTokenAlone() {
        AppMeshClient client = newClient();
        client.refreshToken.set("rt");

        AppMeshClient.RefreshPlan plan = client.computeRefreshPlan();
        assertTrue(plan.due, "a held refresh token can still mint an access token");
        assertEquals(1, plan.delaySeconds);
    }

    /** An opaque token keeps the legacy fixed cadence: the only safe fallback with no lifetime. */
    @Test
    void planFallsBackForUndecodableToken() {
        AppMeshClient client = newClient();
        client.setToken("not-a-jwt");

        AppMeshClient.RefreshPlan plan = client.computeRefreshPlan();
        assertTrue(plan.due);
        assertEquals(300, plan.delaySeconds);
    }

    // The tri-state refresh-token opt-in: a refresh token is a long-lived credential, so a
    // one-shot client (auto-refresh off) must not be issued one it would never store or revoke.

    @Test
    void refreshTokenUnsetFollowsAutoRefresh() {
        assertTrue(new AppMeshClient.Builder().disableSSLVerify().autoRefreshToken(true).build().wantsRefreshToken(),
                "a long-lived client keeps and replays the refresh token");
        assertFalse(new AppMeshClient.Builder().disableSSLVerify().build().wantsRefreshToken(),
                "auto-refresh defaults to off, which is the one-shot case");
    }

    @Test
    void refreshTokenExplicitChoiceOverridesAutoRefresh() {
        assertFalse(new AppMeshClient.Builder().disableSSLVerify().autoRefreshToken(true)
                .useRefreshToken(Boolean.FALSE).build().wantsRefreshToken(),
                "an explicit opt-out must win over auto-refresh");
        assertTrue(new AppMeshClient.Builder().disableSSLVerify()
                .useRefreshToken(Boolean.TRUE).build().wantsRefreshToken(),
                "an explicit opt-in must win over auto-refresh");
    }

    @Test
    void retryDelayBackoffIsBounded() {
        long[] expected = { 5, 10, 20, 40, 60, 60, 60 };
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], AppMeshClient.refreshRetryDelay(i + 1), "failure " + (i + 1));
        }
        assertEquals(60, AppMeshClient.refreshRetryDelay(1000), "backoff must stay bounded");
    }

    @Test
    void decodeJwtTimesReadsExpAndOptionalIat() {
        long[] times = AppMeshClient.decodeJwtTimes(makeJwt(1000, 2000));
        assertEquals(2000, times[0]);
        assertEquals(1000, times[1]);

        // iat is optional; exp is not.
        assertEquals(0, AppMeshClient.decodeJwtTimes(makeJwt(0, 2000))[1]);
        assertThrows(Exception.class, () -> AppMeshClient.decodeJwtTimes("garbage"));
    }
}
