import com.google.gson.Gson;
import java.util.*;
import java.util.regex.*;

/**
 * PhishShield — Java URL Feature Extractor
 * =========================================
 * Standalone CLI utility called by the Flask backend via subprocess.
 * Computes advanced URL features not easily done in Python:
 *   - Shannon domain entropy
 *   - Digit ratio
 *   - Special character count
 *   - N-gram suspicious pattern score
 *
 * Usage:
 *   javac -cp .:gson-2.10.1.jar PhishAnalyzer.java
 *   java  -cp .:gson-2.10.1.jar PhishAnalyzer "http://paypal-secure-login.tk/verify"
 *
 * Outputs: JSON to stdout
 *   {"entropy":3.42,"digitRatio":0.12,"specialChars":5,"ngramScore":0.73,"risk":"HIGH","details":[...]}
 */
public class PhishAnalyzer {

    // ── Known phishing n-gram patterns ───────────────────────────────────────
    private static final String[] PHISH_NGRAMS = {
        "secure", "login", "signin", "verify", "account", "update",
        "banking", "paypal", "amazon", "apple", "microsoft", "netflix",
        "ebay", "dropbox", "google", "facebook", "wellsfargo", "chase",
        "citibank", "password", "credential", "webscr", "confirm",
        "submit", "session", "redirect", "auth", "token", "reset"
    };

    // ── Suspicious TLDs ───────────────────────────────────────────────────────
    private static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
        ".date", ".party", ".click", ".country", ".stream", ".download",
        ".review", ".zip", ".mov"
    ));

    // ── URL shorteners ────────────────────────────────────────────────────────
    private static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "shorturl.at", "tiny.cc", "rebrand.ly"
    ));

    // =========================================================================
    // Entry point
    // =========================================================================
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: PhishAnalyzer <url>");
            System.exit(1);
        }
        String url = args[0].trim();
        Map<String, Object> result = analyze(url);

        // Output as JSON (manual serialization — no external dependency needed)
        System.out.println(toJson(result));
    }

    // =========================================================================
    // Core analysis
    // =========================================================================
    @SuppressWarnings("unchecked")
    public static Map<String, Object> analyze(String rawUrl) {
        // Normalize
        String url = rawUrl.trim();
        if (!url.matches("(?i)^https?://.*")) url = "http://" + url;

        String hostname = extractHostname(url);
        String fullLower = url.toLowerCase();
        String hostLower = hostname.toLowerCase();

        // ── 1. Shannon entropy of the hostname ───────────────────────────────
        double entropy = shannonEntropy(hostLower);

        // ── 2. Digit ratio in full URL ────────────────────────────────────────
        long digitCount = url.chars().filter(Character::isDigit).count();
        double digitRatio = url.isEmpty() ? 0 : (double) digitCount / url.length();

        // ── 3. Special character count ─────────────────────────────────────── 
        long specialChars = url.chars()
            .filter(c -> !Character.isLetterOrDigit(c) && c != '/' && c != '.' && c != ':')
            .count();

        // ── 4. N-gram phishing pattern score ──────────────────────────────────
        int ngramHits = 0;
        List<String> hitPatterns = new ArrayList<>();
        for (String ngram : PHISH_NGRAMS) {
            if (fullLower.contains(ngram)) {
                ngramHits++;
                hitPatterns.add(ngram);
            }
        }
        double ngramScore = Math.min(1.0, ngramHits / 5.0);

        // ── 5. Consecutive consonants (hard to pronounce = generated domain) ─
        int maxConsonants = maxConsecutiveConsonants(hostLower);

        // ── 6. Homoglyph detection ─────────────────────────────────────────── 
        boolean hasHomoglyph = detectHomoglyphs(hostLower);

        // ── 7. TLD risk ────────────────────────────────────────────────────── 
        String tld = extractTld(hostLower);
        boolean isSuspiciousTld = SUSPICIOUS_TLDS.contains(tld);

        // ── 8. Shortener detection ─────────────────────────────────────────── 
        boolean isShortener = SHORTENERS.stream().anyMatch(hostLower::contains);

        // ── 9. Repetitive chars (aaaa, 1111) ──────────────────────────────── 
        boolean hasRepetition = Pattern.compile("(.)\\1{3,}").matcher(hostLower).find();

        // ── 10. Mixed script detection ─────────────────────────────────────── 
        boolean mixedScript = hasMixedScript(url);

        // ── Composite risk score ──────────────────────────────────────────────
        double riskScore = computeRisk(entropy, digitRatio, ngramScore,
            maxConsonants, hasHomoglyph, isSuspiciousTld,
            isShortener, hasRepetition, mixedScript);

        String riskLevel = riskScore >= 0.7 ? "HIGH" : riskScore >= 0.4 ? "MEDIUM" : "LOW";

        // ── Build detail list ─────────────────────────────────────────────────
        List<Map<String, Object>> details = new ArrayList<>();
        addDetail(details, "Domain Entropy",
            String.format("%.2f bits", entropy),
            entropy > 4.0 ? "High entropy — likely algorithmically generated" : "Normal entropy",
            entropy > 4.0);
        addDetail(details, "Digit Ratio",
            String.format("%.0f%%", digitRatio * 100),
            digitRatio > 0.2 ? "High digit density in URL" : "Normal digit ratio",
            digitRatio > 0.2);
        addDetail(details, "Special Characters",
            String.valueOf(specialChars),
            specialChars > 8 ? "Excessive special characters" : "Normal special char count",
            specialChars > 8);
        addDetail(details, "N-gram Pattern Score",
            String.format("%.0f%%", ngramScore * 100),
            ngramHits > 0 ? "Patterns: " + String.join(", ", hitPatterns.subList(0, Math.min(4, hitPatterns.size()))) : "No phishing patterns",
            ngramHits > 0);
        addDetail(details, "Max Consecutive Consonants",
            String.valueOf(maxConsonants),
            maxConsonants >= 4 ? "Suspicious consonant cluster — likely generated domain" : "Normal",
            maxConsonants >= 4);
        addDetail(details, "Homoglyph Characters",
            hasHomoglyph ? "Detected" : "None",
            hasHomoglyph ? "Possible look-alike characters (e.g. rn→m, 0→o)" : "No homoglyphs detected",
            hasHomoglyph);
        addDetail(details, "Mixed Script",
            mixedScript ? "Yes" : "No",
            mixedScript ? "Mixed unicode scripts — possible IDN attack" : "Single script",
            mixedScript);

        // ── Assemble result ───────────────────────────────────────────────────
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("hostname",        hostname);
        result.put("entropy",         Math.round(entropy * 1000.0) / 1000.0);
        result.put("digitRatio",      Math.round(digitRatio * 1000.0) / 1000.0);
        result.put("specialChars",    (int) specialChars);
        result.put("ngramScore",      Math.round(ngramScore * 1000.0) / 1000.0);
        result.put("ngramHits",       ngramHits);
        result.put("ngramPatterns",   hitPatterns);
        result.put("maxConsonants",   maxConsonants);
        result.put("hasHomoglyph",    hasHomoglyph);
        result.put("isSuspiciousTld", isSuspiciousTld);
        result.put("isShortener",     isShortener);
        result.put("hasRepetition",   hasRepetition);
        result.put("mixedScript",     mixedScript);
        result.put("riskScore",       Math.round(riskScore * 1000.0) / 1000.0);
        result.put("risk",            riskLevel);
        result.put("details",         details);
        return result;
    }

    // =========================================================================
    // Feature helpers
    // =========================================================================

    /** Shannon entropy: H = -Σ p(c) * log2(p(c)) */
    private static double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.merge(c, 1, Integer::sum);
        double entropy = 0.0;
        int len = s.length();
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    /** Maximum consecutive consonants in a word */
    private static int maxConsecutiveConsonants(String s) {
        String consonants = "bcdfghjklmnpqrstvwxyz";
        int max = 0, current = 0;
        for (char c : s.toCharArray()) {
            if (consonants.indexOf(c) >= 0) { current++; max = Math.max(max, current); }
            else current = 0;
        }
        return max;
    }

    /** Detect common homoglyph pairs */
    private static boolean detectHomoglyphs(String s) {
        // Common homoglyph substitutions used in phishing
        String[][] pairs = {{"0", "o"}, {"1", "l"}, {"rn", "m"}, {"vv", "w"}};
        for (String[] pair : pairs) {
            if (s.contains(pair[0]) && s.contains(pair[1])) return true;
        }
        // Check for non-ASCII in hostname
        for (char c : s.toCharArray()) if (c > 127) return true;
        return false;
    }

    /** Mixed Unicode script detection */
    private static boolean hasMixedScript(String s) {
        boolean hasLatin = false, hasOther = false;
        for (char c : s.toCharArray()) {
            if (c < 128) { if (Character.isLetter(c)) hasLatin = true; }
            else if (Character.isLetter(c)) hasOther = true;
        }
        return hasLatin && hasOther;
    }

    /** Composite risk score [0..1] */
    private static double computeRisk(double entropy, double digitRatio,
            double ngramScore, int maxConsonants,
            boolean hasHomoglyph, boolean isSuspTld,
            boolean isShortener, boolean hasRepetition,
            boolean mixedScript) {
        double score = 0.0;
        if (entropy > 4.5)       score += 0.25;
        else if (entropy > 3.8)  score += 0.12;
        if (digitRatio > 0.25)   score += 0.15;
        else if (digitRatio > 0.1) score += 0.07;
        score += ngramScore * 0.20;
        if (maxConsonants >= 5)  score += 0.15;
        else if (maxConsonants >= 4) score += 0.08;
        if (hasHomoglyph)  score += 0.15;
        if (isSuspTld)     score += 0.10;
        if (isShortener)   score += 0.08;
        if (hasRepetition) score += 0.06;
        if (mixedScript)   score += 0.12;
        return Math.min(1.0, score);
    }

    /** Extract hostname from URL string */
    private static String extractHostname(String url) {
        try {
            String h = url.replaceFirst("(?i)^https?://", "");
            h = h.split("[/?#]")[0];
            h = h.split("@")[h.split("@").length - 1]; // handle user@host
            h = h.split(":")[0]; // remove port
            return h.toLowerCase();
        } catch (Exception e) { return url; }
    }

    /** Extract TLD (last dot-segment) */
    private static String extractTld(String hostname) {
        String[] parts = hostname.split("\\.");
        return parts.length > 0 ? "." + parts[parts.length - 1] : "";
    }

    /** Add a detail entry to the list */
    private static void addDetail(List<Map<String, Object>> list,
            String name, String value, String message, boolean flagged) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("name", name);
        d.put("value", value);
        d.put("message", message);
        d.put("flagged", flagged);
        list.add(d);
    }

    // =========================================================================
    // Minimal JSON serializer (no external deps needed)
    // =========================================================================
    @SuppressWarnings("unchecked")
    private static String toJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof String) return "\"" + escape((String) obj) + "\"";
        if (obj instanceof Boolean || obj instanceof Number) return obj.toString();
        if (obj instanceof List) {
            StringBuilder sb = new StringBuilder("[");
            List<?> list = (List<?>) obj;
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(toJson(list.get(i)));
            }
            return sb.append("]").toString();
        }
        if (obj instanceof Map) {
            StringBuilder sb = new StringBuilder("{");
            Map<String, Object> map = (Map<String, Object>) obj;
            boolean first = true;
            for (Map.Entry<String, Object> e : map.entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(escape(e.getKey())).append("\":").append(toJson(e.getValue()));
                first = false;
            }
            return sb.append("}").toString();
        }
        return "\"" + escape(obj.toString()) + "\"";
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
