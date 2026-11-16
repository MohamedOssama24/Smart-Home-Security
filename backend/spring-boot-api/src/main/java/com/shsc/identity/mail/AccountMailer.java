package com.shsc.identity.mail;

import java.net.URI;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.MessageSource;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import com.shsc.shared.config.ShscProperties;

/**
 * Account e-mails (IT/EN). Sent asynchronously and only after the transaction commits:
 * response time does not depend on whether an e-mail is sent (no account enumeration
 * through timing), and no e-mail leaves for data that was rolled back. Raw tokens are never
 * persisted nor logged; they travel only inside the e-mail, in the URL fragment
 * ({@code #token=...}), which browsers do not send to servers or in Referer headers.
 */
@Service
public class AccountMailer implements DisposableBean {

    private static final Logger LOG = LoggerFactory.getLogger(AccountMailer.class);

    public enum Kind { VERIFY_EMAIL, RESET_PASSWORD, ACCOUNT_EXISTS, INVITATION }

    private final JavaMailSender sender;
    private final MessageSource messages;
    private final URI baseUrl;
    private final String from;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public AccountMailer(JavaMailSender sender, MessageSource messages, ShscProperties properties) {
        this.sender = sender;
        this.messages = messages;
        this.baseUrl = properties.publicBaseUrl();
        this.from = properties.mail().from();
    }

    public void verifyEmail(String to, String locale, String displayName, String token) {
        schedule(Kind.VERIFY_EMAIL, to, locale, displayName, link("/verify-email", token));
    }

    public void resetPassword(String to, String locale, String displayName, String token) {
        schedule(Kind.RESET_PASSWORD, to, locale, displayName, link("/reset-password", token));
    }

    /** Sent when someone tries to register an e-mail that already has an account. */
    public void accountExists(String to, String locale, String displayName) {
        schedule(Kind.ACCOUNT_EXISTS, to, locale, displayName, baseUrl.resolve("/forgot-password").toString());
    }

    /** Invitation of a new user by an administrator: the link lets the user choose a password. */
    public void invitation(String to, String locale, String displayName, String inviterName, String organizationName,
            String token, long validDays) {
        schedule(Kind.INVITATION, to, locale, displayName, link("/accept-invitation", token), inviterName,
                organizationName, validDays);
    }

    private String link(String path, String token) {
        return baseUrl.resolve(path) + "#token=" + token;
    }

    private void schedule(Kind kind, String to, String locale, String displayName, String link, Object... extra) {
        SimpleMailMessage message = build(kind, to, locale, displayName, link, extra);
        Runnable send = () -> executor.execute(() -> deliver(kind, message));
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    send.run();
                }
            });
        } else {
            send.run();
        }
    }

    SimpleMailMessage build(Kind kind, String to, String locale, String displayName, String link, Object... extra) {
        Locale lang = Locale.forLanguageTag("en".equals(locale) ? "en" : "it");
        String prefix = "mail." + kind.name().toLowerCase(Locale.ROOT).replace('_', '-');
        Object[] args = new Object[2 + extra.length];
        args[0] = displayName;
        args[1] = link;
        System.arraycopy(extra, 0, args, 2, extra.length);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject(messages.getMessage(prefix + ".subject", args, lang));
        message.setText(messages.getMessage(prefix + ".body", args, lang));
        return message;
    }

    private void deliver(Kind kind, SimpleMailMessage message) {
        try {
            sender.send(message);
        } catch (MailException e) {
            // never log the message body: it contains a one-time token
            LOG.error("Could not send {} e-mail: {}", kind, e.getMessage());
        }
    }

    @Override
    public void destroy() {
        executor.close();
    }
}
