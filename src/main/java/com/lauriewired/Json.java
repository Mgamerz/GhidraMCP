package com.lauriewired;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON writer and parser.
 *
 * <p>GhidraMCP deliberately avoids adding a JSON library to the extension: the plugin is loaded by
 * Ghidra's module class loader and only the jars listed in {@code pom.xml} (all of which ship with
 * Ghidra itself) are guaranteed to be visible. The subset implemented here -- objects, arrays,
 * strings, numbers, booleans and null -- is all the HTTP API needs.
 */
final class Json {

    private Json() {
    }

    // ------------------------------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------------------------------

    /** Render a Java string as a JSON string literal, including the surrounding quotes. */
    static String quote(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    // Escape control characters and everything outside printable ASCII so the
                    // response survives any charset confusion between plugin and bridge.
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }

    /** Join already-rendered JSON values into an array. */
    static String array(List<String> renderedItems) {
        return "[" + String.join(",", renderedItems) + "]";
    }

    /** A one-key {@code {"error": "..."}} document. */
    static String error(String message) {
        return new Obj().str("error", message).done();
    }

    /** Incremental JSON object writer. Keys are emitted in insertion order. */
    static final class Obj {
        private final StringBuilder sb = new StringBuilder("{");
        private boolean first = true;

        private void separate() {
            if (!first) sb.append(',');
            first = false;
        }

        /** Add a key whose value is an already-rendered JSON fragment. */
        Obj raw(String key, String renderedValue) {
            separate();
            sb.append(quote(key)).append(':').append(renderedValue);
            return this;
        }

        Obj str(String key, String value) {
            return raw(key, quote(value));
        }

        Obj num(String key, long value) {
            return raw(key, Long.toString(value));
        }

        Obj bool(String key, boolean value) {
            return raw(key, Boolean.toString(value));
        }

        Obj nul(String key) {
            return raw(key, "null");
        }

        String done() {
            return sb.append('}').toString();
        }
    }

    // ------------------------------------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------------------------------------

    /** Thrown for any malformed input; the message carries the offset. */
    static final class JsonException extends Exception {
        JsonException(String message) {
            super(message);
        }
    }

    /**
     * Parse a JSON document into {@code Map<String,Object>}, {@code List<Object>}, {@code String},
     * {@code Long}, {@code Double}, {@code Boolean} or {@code null}.
     */
    static Object parse(String text) throws JsonException {
        Parser p = new Parser(text);
        p.skipWhitespace();
        Object value = p.parseValue();
        p.skipWhitespace();
        if (!p.atEnd()) {
            throw new JsonException("trailing content at offset " + p.pos);
        }
        return value;
    }

    /** Convenience: parse and require the result to be an array of objects. */
    static List<Map<String, Object>> parseObjectArray(String text) throws JsonException {
        Object root = parse(text);
        if (!(root instanceof List)) {
            throw new JsonException("expected a JSON array at the top level");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        int i = 0;
        for (Object item : (List<?>) root) {
            if (!(item instanceof Map)) {
                throw new JsonException("array element " + i + " is not an object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) item;
            out.add(m);
            i++;
        }
        return out;
    }

    /** Read a string-valued key, returning null when absent or JSON null. */
    static String optString(Map<String, Object> obj, String key) {
        Object v = obj.get(key);
        if (v == null) return null;
        return (v instanceof String) ? (String) v : String.valueOf(v);
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        void skipWhitespace() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object parseValue() throws JsonException {
            if (atEnd()) throw new JsonException("unexpected end of input");
            char c = s.charAt(pos);
            switch (c) {
                case '{': return parseObject();
                case '[': return parseArray();
                case '"': return parseString();
                case 't': expect("true");  return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null");  return null;
                default:  return parseNumber();
            }
        }

        private void expect(String literal) throws JsonException {
            if (!s.startsWith(literal, pos)) {
                throw new JsonException("expected '" + literal + "' at offset " + pos);
            }
            pos += literal.length();
        }

        private Map<String, Object> parseObject() throws JsonException {
            pos++; // consume '{'
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (!atEnd() && s.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (atEnd() || s.charAt(pos) != '"') {
                    throw new JsonException("expected an object key at offset " + pos);
                }
                String key = parseString();
                skipWhitespace();
                if (atEnd() || s.charAt(pos) != ':') {
                    throw new JsonException("expected ':' at offset " + pos);
                }
                pos++;
                skipWhitespace();
                map.put(key, parseValue());
                skipWhitespace();
                if (atEnd()) throw new JsonException("unterminated object");
                char c = s.charAt(pos++);
                if (c == '}') return map;
                if (c != ',') throw new JsonException("expected ',' or '}' at offset " + (pos - 1));
            }
        }

        private List<Object> parseArray() throws JsonException {
            pos++; // consume '['
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (!atEnd() && s.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                skipWhitespace();
                list.add(parseValue());
                skipWhitespace();
                if (atEnd()) throw new JsonException("unterminated array");
                char c = s.charAt(pos++);
                if (c == ']') return list;
                if (c != ',') throw new JsonException("expected ',' or ']' at offset " + (pos - 1));
            }
        }

        private String parseString() throws JsonException {
            pos++; // consume the opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) throw new JsonException("unterminated string");
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (atEnd()) throw new JsonException("unterminated escape");
                char e = s.charAt(pos++);
                switch (e) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case '/':  sb.append('/');  break;
                    case 'b':  sb.append('\b'); break;
                    case 'f':  sb.append('\f'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    case 'u':
                        if (pos + 4 > s.length()) throw new JsonException("truncated unicode escape");
                        sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        pos += 4;
                        break;
                    default:
                        throw new JsonException("bad escape at offset " + (pos - 1));
                }
            }
        }

        private Object parseNumber() throws JsonException {
            int start = pos;
            if (!atEnd() && (s.charAt(pos) == '-' || s.charAt(pos) == '+')) pos++;
            boolean floating = false;
            while (!atEnd()) {
                char c = s.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                }
                else if (c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') {
                    floating = true;
                    pos++;
                }
                else {
                    break;
                }
            }
            String token = s.substring(start, pos);
            if (token.isEmpty()) throw new JsonException("expected a value at offset " + start);
            try {
                return floating ? (Object) Double.valueOf(token) : (Object) Long.valueOf(token);
            }
            catch (NumberFormatException e) {
                throw new JsonException("bad number at offset " + start);
            }
        }
    }
}
