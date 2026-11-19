package com.shsc.support;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.shsc.alerts.push.PushGateway;

import tools.jackson.databind.json.JsonMapper;

/**
 * Base class of the HTTP integration tests: real server on a random port, real PostgreSQL
 * 18 with RLS and the real role model. Only the SMTP sender is replaced, to read the
 * e-mails (and their one-time links) the application sends, and the FCM push gateway.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public abstract class IntegrationTest {

    @DynamicPropertySource
    static void environment(DynamicPropertyRegistry registry) {
        PostgresTestContainer.register(registry);
    }

    @LocalServerPort
    protected int port;

    @MockitoBean
    protected JavaMailSender mailSender;

    /** FCM is never called: disabled unless a test enables it ({@code when(push.enabled())}). */
    @MockitoBean
    protected PushGateway push;

    @Autowired
    protected JsonMapper json;

    protected ApiClient client() {
        return new ApiClient("http://localhost:" + port, json);
    }

    protected Mailbox mailbox() {
        return new Mailbox(mailSender);
    }

    protected TestAccounts accounts() {
        return new TestAccounts(this::client, mailbox());
    }
}
