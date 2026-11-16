package com.shsc.support;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.mockito.Mockito;
import org.mockito.invocation.Invocation;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/** Reads the e-mails passed to the (mocked) JavaMailSender. Sending is asynchronous. */
public class Mailbox {

    private static final Pattern TOKEN = Pattern.compile("#token=([A-Za-z0-9_\\-]+)");

    private final JavaMailSender sender;

    public Mailbox(JavaMailSender sender) {
        this.sender = sender;
    }

    public List<SimpleMailMessage> messagesTo(String email) {
        return Mockito.mockingDetails(sender).getInvocations().stream()
                .map(Invocation::getArguments)
                .filter(args -> args.length == 1 && args[0] instanceof SimpleMailMessage)
                .map(args -> (SimpleMailMessage) args[0])
                .filter(m -> m.getTo() != null && List.of(m.getTo()).contains(email))
                .toList();
    }

    /** Waits for the n-th (1-based) message to the address. */
    public SimpleMailMessage await(String email, int count) {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(10));
        while (Instant.now().isBefore(deadline)) {
            List<SimpleMailMessage> messages = messagesTo(email);
            if (messages.size() >= count) {
                return messages.get(count - 1);
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
        throw new AssertionError("No e-mail #" + count + " for " + email);
    }

    public static Optional<String> token(SimpleMailMessage message) {
        Matcher matcher = TOKEN.matcher(message.getText());
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }
}
