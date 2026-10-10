package com.socanalyzer.phishingdetector.analyzer;

/**
 * A URL found in the email, paired with the visible anchor text if it came
 * from an HTML <a href="..."> tag (needed to detect displayed-vs-actual
 * mismatch, requirement #5). For plain-text URLs, displayedText == href.
 */
public record ParsedLink(String href, String displayedText, boolean fromHtml) {}
