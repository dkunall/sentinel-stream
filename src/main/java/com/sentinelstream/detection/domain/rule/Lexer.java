package com.sentinelstream.detection.domain.rule;

import java.util.ArrayList;
import java.util.List;

/** Splits rule text into tokens. Words are lower-cased (the DSL is case-insensitive); strings are kept as written. */
final class Lexer {

    enum Type { WORD, NUMBER, DURATION, STRING, SYMBOL, END }

    record Token(Type type, String text, int pos) {
        boolean is(String s) {
            return (type == Type.WORD || type == Type.SYMBOL) && text.equals(s);
        }

        @Override
        public String toString() {
            return type == Type.END ? "end of rule" : "'" + text + "'";
        }
    }

    static List<Token> tokenize(String src) {
        List<Token> out = new ArrayList<>();
        int i = 0, n = src.length();
        while (i < n) {
            char c = src.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '#') {
                while (i < n && src.charAt(i) != '\n') {
                    i++;
                }
            } else if (Character.isLetter(c) || c == '_') {
                int s = i;
                while (i < n && (Character.isLetterOrDigit(src.charAt(i)) || src.charAt(i) == '_')) {
                    i++;
                }
                out.add(new Token(Type.WORD, src.substring(s, i).toLowerCase(), s));
            } else if (Character.isDigit(c)) {
                int s = i;
                while (i < n && Character.isDigit(src.charAt(i))) {
                    i++;
                }
                if (i + 1 < n && src.charAt(i) == '.' && Character.isDigit(src.charAt(i + 1))) {
                    i++;
                    while (i < n && Character.isDigit(src.charAt(i))) {
                        i++;
                    }
                    out.add(new Token(Type.NUMBER, src.substring(s, i), s));
                } else if (i < n && "smhd".indexOf(src.charAt(i)) >= 0
                        && (i + 1 == n || !Character.isLetterOrDigit(src.charAt(i + 1)))) {
                    i++;
                    out.add(new Token(Type.DURATION, src.substring(s, i), s));
                } else {
                    out.add(new Token(Type.NUMBER, src.substring(s, i), s));
                }
            } else if (c == '"') {
                int s = i++;
                StringBuilder b = new StringBuilder();
                while (true) {
                    if (i >= n) {
                        throw new RuleSyntaxException("unterminated string", s);
                    }
                    char d = src.charAt(i++);
                    if (d == '"') {
                        break;
                    }
                    if (d == '\\' && i < n) {
                        d = src.charAt(i++);
                    }
                    b.append(d);
                }
                out.add(new Token(Type.STRING, b.toString(), s));
            } else if ((c == '!' || c == '>') && i + 1 < n && src.charAt(i + 1) == '=') {
                out.add(new Token(Type.SYMBOL, src.substring(i, i + 2), i));
                i += 2;
            } else if (".*{},()=>".indexOf(c) >= 0) {
                out.add(new Token(Type.SYMBOL, String.valueOf(c), i));
                i++;
            } else {
                throw new RuleSyntaxException("unexpected character '" + c + "'", i);
            }
        }
        out.add(new Token(Type.END, "", n));
        return out;
    }
}
