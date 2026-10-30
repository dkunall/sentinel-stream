package com.sentinelstream.detection.domain.engine;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Multi-pattern substring matcher: one pass over the text finds every pattern, O(text + matches)
 * however many patterns there are. Case-insensitive (patterns and text are lower-cased).
 */
public final class AhoCorasick {

    private static final class Node {
        final Map<Character, Node> next = new HashMap<>();
        Node fail;
        final List<String> out = new ArrayList<>();
    }

    private final Node root = new Node();
    private final int size;

    public AhoCorasick(Iterable<String> patterns) {
        int n = 0;
        for (String p : patterns) {
            if (p == null || p.isEmpty()) {
                continue;
            }
            String lower = p.toLowerCase();
            Node cur = root;
            for (char c : lower.toCharArray()) {
                cur = cur.next.computeIfAbsent(c, k -> new Node());
            }
            if (cur.out.isEmpty()) {
                n++;
            }
            if (!cur.out.contains(lower)) {
                cur.out.add(lower);
            }
        }
        this.size = n;
        ArrayDeque<Node> queue = new ArrayDeque<>();
        root.fail = root;
        for (Node child : root.next.values()) {
            child.fail = root;
            queue.add(child);
        }
        while (!queue.isEmpty()) {
            Node node = queue.poll();
            for (Map.Entry<Character, Node> e : node.next.entrySet()) {
                char c = e.getKey();
                Node child = e.getValue();
                Node f = node.fail;
                while (f != root && !f.next.containsKey(c)) {
                    f = f.fail;
                }
                Node target = f.next.get(c);
                child.fail = (target != null && target != child) ? target : root;
                child.out.addAll(child.fail.out);
                queue.add(child);
            }
        }
    }

    public int size() {
        return size;
    }

    /** Every pattern occurring in {@code text}, in order of where it ends. */
    public List<String> findAll(String text) {
        List<String> found = new ArrayList<>();
        if (text == null) {
            return found;
        }
        Node cur = root;
        for (char c : text.toLowerCase().toCharArray()) {
            while (cur != root && !cur.next.containsKey(c)) {
                cur = cur.fail;
            }
            cur = cur.next.getOrDefault(c, root);
            found.addAll(cur.out);
        }
        return found;
    }

    public Optional<String> firstMatch(String text) {
        if (text == null) {
            return Optional.empty();
        }
        Node cur = root;
        for (char c : text.toLowerCase().toCharArray()) {
            while (cur != root && !cur.next.containsKey(c)) {
                cur = cur.fail;
            }
            cur = cur.next.getOrDefault(c, root);
            if (!cur.out.isEmpty()) {
                return Optional.of(cur.out.getFirst());
            }
        }
        return Optional.empty();
    }
}
