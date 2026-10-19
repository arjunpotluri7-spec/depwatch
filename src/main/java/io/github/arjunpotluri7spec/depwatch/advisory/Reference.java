package io.github.arjunpotluri7spec.depwatch.advisory;

/** An OSV reference: a type such as {@code ADVISORY} or {@code FIX} and a URL. */
public record Reference(String type, String url) {}
