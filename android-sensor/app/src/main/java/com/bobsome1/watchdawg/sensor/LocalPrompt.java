package com.bobsome1.watchdawg.sensor;

final class LocalPrompt {
    static final int MAX_CHARS = 4000;

    private LocalPrompt() {}

    static String validate(String input) {
        if (input.length() > MAX_CHARS) throw new IllegalArgumentException("Questions are limited to 4,000 characters.");
        String prompt = input.trim();
        if (prompt.isEmpty()) throw new IllegalArgumentException("Enter a question first.");
        return prompt;
    }
}
