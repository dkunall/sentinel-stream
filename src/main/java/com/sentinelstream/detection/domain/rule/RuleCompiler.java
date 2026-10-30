package com.sentinelstream.detection.domain.rule;

import com.sentinelstream.event.EnrichedEvent;
import com.sentinelstream.event.Outcome;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Recursive-descent parser for the rule DSL. Examples:
 * <pre>
 * sequence login.failure{5,} then login.success where asn is new by user within 10m
 * threshold login.failure >= 20 by ip within 5m
 * anomaly login.failure by user per 1h zscore > 3 after 24
 * ioc user_agent in "bad-agents"
 * travel login.success by user faster than 900 kmh
 * newdevice login.success by user after 3
 * </pre>
 * The canonical text printed back from the parse tree is what gets hashed, so whitespace, keyword
 * case and comments do not change a rule's identity. Thread-safe: each call parses with its own token
 * cursor, so one instance can be shared (an earlier version kept the cursor on the shared instance and
 * concurrent saves corrupted each other's parse).
 */
public final class RuleCompiler {

    private static final Set<String> IS_NEW_FIELDS = Set.of("asn", "country", "city", "device", "ip", "user", "network");
    private static final Duration MAX_WINDOW = Duration.ofDays(1);

    private final List<Lexer.Token> tokens;
    private int at;

    public RuleCompiler() {
        this.tokens = List.of();
    }

    private RuleCompiler(List<Lexer.Token> tokens) {
        this.tokens = tokens;
    }

    public CompiledRule compile(String dsl) {
        if (dsl == null || dsl.isBlank()) {
            throw new RuleSyntaxException("empty rule", 0);
        }
        if (dsl.length() > 2000) {
            throw new RuleSyntaxException("rule longer than 2000 characters", 2000);
        }
        return new RuleCompiler(Lexer.tokenize(dsl)).parse();
    }

    private CompiledRule parse() {
        Lexer.Token head = next();
        RuleSpec spec = switch (head.text()) {
            case "sequence" -> sequence();
            case "threshold" -> threshold();
            case "anomaly" -> anomaly();
            case "ioc" -> ioc();
            case "travel" -> travel();
            case "newdevice" -> newDevice();
            default -> throw new RuleSyntaxException(
                    "a rule starts with sequence, threshold, anomaly, ioc, travel or newdevice, not " + head, head.pos());
        };
        Lexer.Token end = peek();
        if (end.type() != Lexer.Type.END) {
            throw new RuleSyntaxException("unexpected " + end, end.pos());
        }
        String canonical = canonical(spec);
        return new CompiledRule(spec, canonical, sha256(canonical));
    }

    private RuleSpec sequence() {
        List<Step> steps = new ArrayList<>();
        steps.add(step(true));
        while (accept("then")) {
            steps.add(step(true));
        }
        if (steps.size() > 8) {
            throw new RuleSyntaxException("at most 8 steps", peek().pos());
        }
        if (steps.getFirst().where().stream().anyMatch(c -> c instanceof Condition.Same || c instanceof Condition.Changed)) {
            throw new RuleSyntaxException("the first step has nothing earlier to compare with (same/changed)", 0);
        }
        EntityKind by = by();
        expect("within");
        Duration w = duration();
        if (w.compareTo(MAX_WINDOW) > 0) {
            throw new RuleSyntaxException("window longer than 1d", peek().pos());
        }
        return new RuleSpec.Sequence(steps, by, w);
    }

    private RuleSpec threshold() {
        Step s = step(false);
        expect(">=");
        int count = integer(2, 100_000);
        EntityKind by = by();
        expect("within");
        Duration w = duration();
        if (w.compareTo(MAX_WINDOW) > 0) {
            throw new RuleSyntaxException("window longer than 1d", peek().pos());
        }
        return new RuleSpec.Threshold(s, count, by, w);
    }

    private RuleSpec anomaly() {
        Step s = step(false);
        EntityKind by = by();
        expect("per");
        Duration bucket = duration();
        if (bucket.toMinutes() < 1 || bucket.compareTo(MAX_WINDOW) > 0) {
            throw new RuleSyntaxException("bucket must be between 1m and 1d", peek().pos());
        }
        expect("zscore");
        expect(">");
        double z = number();
        expect("after");
        int after = integer(2, 10_000);
        return new RuleSpec.Anomaly(s, by, bucket, z, after);
    }

    private RuleSpec ioc() {
        Lexer.Token f = next();
        if (!f.is("ip") && !f.is("user_agent")) {
            throw new RuleSyntaxException("ioc matches ip or user_agent, not " + f, f.pos());
        }
        expect("in");
        Lexer.Token list = next();
        if (list.type() != Lexer.Type.STRING || !list.text().matches("[a-z0-9-]{1,64}")) {
            throw new RuleSyntaxException("ioc list name must be a quoted [a-z0-9-] name", list.pos());
        }
        EntityKind by = peek().is("by") ? by() : EntityKind.IP;
        return new RuleSpec.Ioc(f.text(), list.text(), by);
    }

    private RuleSpec travel() {
        Step s = step(false);
        EntityKind by = by();
        if (by != EntityKind.USER) {
            throw new RuleSyntaxException("travel is tracked per user", peek().pos());
        }
        expect("faster");
        expect("than");
        double kmh = number();
        expect("kmh");
        return new RuleSpec.Travel(s, by, kmh);
    }

    private RuleSpec newDevice() {
        Step s = step(false);
        EntityKind by = by();
        expect("after");
        int after = integer(1, 10_000);
        return new RuleSpec.NewDevice(s, by, after);
    }

    private Step step(boolean quantified) {
        EventPattern pattern = pattern();
        int min = 1, max = 1;
        if (quantified && accept("{")) {
            min = integer(1, 1000);
            if (accept(",")) {
                max = peek().type() == Lexer.Type.NUMBER ? integer(min, 1000) : Step.UNBOUNDED;
            } else {
                max = min;
            }
            expect("}");
        }
        List<Condition> where = new ArrayList<>();
        if (accept("where")) {
            where.add(condition());
            while (accept("and")) {
                where.add(condition());
            }
        }
        return new Step(pattern, where, min, max);
    }

    private EventPattern pattern() {
        Lexer.Token a = next();
        String action;
        if (a.is("*")) {
            action = null;
        } else if (a.type() == Lexer.Type.WORD) {
            action = a.text();
        } else {
            throw new RuleSyntaxException("expected an action like login, got " + a, a.pos());
        }
        expect(".");
        Lexer.Token o = next();
        Outcome outcome;
        if (o.is("*")) {
            outcome = null;
        } else if (o.is("success") || o.is("failure")) {
            outcome = Outcome.valueOf(o.text().toUpperCase());
        } else {
            throw new RuleSyntaxException("outcome is success, failure or *, not " + o, o.pos());
        }
        return new EventPattern(action, outcome);
    }

    private Condition condition() {
        Lexer.Token f = next();
        if (f.type() != Lexer.Type.WORD || !EnrichedEvent.FIELDS.contains(f.text())) {
            throw new RuleSyntaxException("unknown field " + f + "; fields are " + EnrichedEvent.FIELDS.stream().sorted()
                    .collect(Collectors.joining(", ")), f.pos());
        }
        String field = f.text();
        Lexer.Token op = next();
        if (op.is("=") || op.is("!=")) {
            return new Condition.Equals(field, value(), op.is("!="));
        }
        if (op.is("is")) {
            expect("new");
            if (!IS_NEW_FIELDS.contains(field)) {
                throw new RuleSyntaxException("'is new' is tracked for " + IS_NEW_FIELDS, op.pos());
            }
            return new Condition.IsNew(field);
        }
        if (op.is("same")) {
            return new Condition.Same(field);
        }
        if (op.is("changed")) {
            return new Condition.Changed(field);
        }
        boolean negated = false;
        if (op.is("not")) {
            negated = true;
            op = next();
        }
        if (op.is("in")) {
            expect("(");
            List<String> values = new ArrayList<>();
            values.add(value());
            while (accept(",")) {
                values.add(value());
            }
            expect(")");
            return new Condition.In(field, values, negated);
        }
        throw new RuleSyntaxException("expected =, !=, in, is new, same or changed after " + field, op.pos());
    }

    private String value() {
        Lexer.Token v = next();
        if (v.type() == Lexer.Type.STRING || v.type() == Lexer.Type.WORD || v.type() == Lexer.Type.NUMBER) {
            return v.text();
        }
        throw new RuleSyntaxException("expected a value, got " + v, v.pos());
    }

    private EntityKind by() {
        expect("by");
        Lexer.Token f = next();
        try {
            return EntityKind.byField(f.text());
        } catch (IllegalArgumentException e) {
            throw new RuleSyntaxException(e.getMessage(), f.pos());
        }
    }

    private Duration duration() {
        Lexer.Token t = next();
        if (t.type() != Lexer.Type.DURATION) {
            throw new RuleSyntaxException("expected a duration like 10m, got " + t, t.pos());
        }
        long n = Long.parseLong(t.text().substring(0, t.text().length() - 1));
        Duration d = switch (t.text().charAt(t.text().length() - 1)) {
            case 's' -> Duration.ofSeconds(n);
            case 'm' -> Duration.ofMinutes(n);
            case 'h' -> Duration.ofHours(n);
            default -> Duration.ofDays(n);
        };
        if (d.isZero()) {
            throw new RuleSyntaxException("duration must be positive", t.pos());
        }
        return d;
    }

    private int integer(int min, int max) {
        Lexer.Token t = next();
        if (t.type() != Lexer.Type.NUMBER || t.text().contains(".")) {
            throw new RuleSyntaxException("expected a whole number, got " + t, t.pos());
        }
        int v;
        try {
            v = Integer.parseInt(t.text());
        } catch (NumberFormatException e) {
            throw new RuleSyntaxException("number too large", t.pos());
        }
        if (v < min || v > max) {
            throw new RuleSyntaxException("expected " + min + ".." + max + ", got " + v, t.pos());
        }
        return v;
    }

    private double number() {
        Lexer.Token t = next();
        if (t.type() != Lexer.Type.NUMBER) {
            throw new RuleSyntaxException("expected a number, got " + t, t.pos());
        }
        return Double.parseDouble(t.text());
    }

    private void expect(String s) {
        Lexer.Token t = next();
        if (!t.is(s)) {
            throw new RuleSyntaxException("expected '" + s + "', got " + t, t.pos());
        }
    }

    private boolean accept(String s) {
        if (peek().is(s)) {
            at++;
            return true;
        }
        return false;
    }

    private Lexer.Token peek() {
        return tokens.get(at);
    }

    private Lexer.Token next() {
        Lexer.Token t = tokens.get(at);
        if (t.type() != Lexer.Type.END) {
            at++;
        }
        return t;
    }

    static String canonical(RuleSpec spec) {
        return switch (spec) {
            case RuleSpec.Sequence s -> "sequence " + s.steps().stream().map(Step::canonical).collect(Collectors.joining(" then "))
                    + " by " + s.entity().field() + " within " + dur(s.within());
            case RuleSpec.Threshold t -> "threshold " + t.step().canonical() + " >= " + t.count() + " by " + t.entity().field()
                    + " within " + dur(t.within());
            case RuleSpec.Anomaly a -> "anomaly " + a.step().canonical() + " by " + a.entity().field() + " per " + dur(a.bucket())
                    + " zscore > " + num(a.zScore()) + " after " + a.minObservations();
            case RuleSpec.Ioc i -> "ioc " + i.field() + " in \"" + i.list() + "\" by " + i.entity().field();
            case RuleSpec.Travel t -> "travel " + t.step().canonical() + " by " + t.entity().field() + " faster than "
                    + num(t.maxKmh()) + " kmh";
            case RuleSpec.NewDevice n -> "newdevice " + n.step().canonical() + " by " + n.entity().field() + " after " + n.after();
        };
    }

    private static String dur(Duration d) {
        long s = d.toSeconds();
        if (s % 86400 == 0) {
            return s / 86400 + "d";
        }
        if (s % 3600 == 0) {
            return s / 3600 + "h";
        }
        if (s % 60 == 0) {
            return s / 60 + "m";
        }
        return s + "s";
    }

    private static String num(double v) {
        return v == Math.rint(v) ? String.valueOf((long) v) : String.valueOf(v);
    }

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
