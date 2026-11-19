package com.shsc.assistant;

import java.util.List;

/**
 * Port of the AI assistant (docs/25-AI-ASSISTANT.md). A provider only produces text from the
 * facts it receives: it has no tools, no database access and cannot act. Every answer of a
 * provider other than LOCAL is checked by {@link GroundingValidator} before being shown.
 */
public interface AssistantProvider {

    /** LOCAL, OLLAMA... */
    String name();

    /** False when the provider is not configured (the service then answers with LOCAL). */
    boolean available();

    Draft answer(String question, String locale, AssistantFacts facts);

    /** Answer text with inline citations like [F1]; {@code citations} as declared by the provider. */
    record Draft(String text, List<String> citations) {
    }

    /** The provider could not answer (unreachable, timeout, invalid output): never shown to the user. */
    class ProviderException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public ProviderException(String message) {
            super(message);
        }

        public ProviderException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
