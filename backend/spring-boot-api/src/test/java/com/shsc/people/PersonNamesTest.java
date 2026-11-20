package com.shsc.people;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Person names in the names announced by devices (M24). [MOCK] names. */
class PersonNamesTest {

    private static String name(String deviceName) {
        return PersonNames.find(deviceName).map(PersonNames.Found::name).orElse(null);
    }

    @Test
    void ownerAfterTheDevice() {
        assertThat(name("iPhone-di-Marco")).isEqualTo("Marco");
        assertThat(name("iPhone di Marco")).isEqualTo("Marco");
        assertThat(name("Galaxy-S21-di-Giulia")).isEqualTo("Giulia");
        assertThat(name("MacBook-Pro-di-Luca-Rossi.local")).isEqualTo("Luca Rossi");
        assertThat(name("Pixel-7-of-ANNA")).isEqualTo("Anna");
        assertThat(PersonNames.find("iPhone-di-Marco.local").orElseThrow().evidence())
                .isEqualTo("iPhone-di-Marco.local");
    }

    @Test
    void ownerBeforeTheDevice() {
        assertThat(name("Marcos-iPhone")).isEqualTo("Marco");   // Apple: "Marco's iPhone"
        assertThat(name("Marco's iPhone")).isEqualTo("Marco");
        assertThat(name("Giulias-MacBook-Pro")).isEqualTo("Giulia");
        assertThat(name("Luca-PC")).isEqualTo("Luca");
        assertThat(name("Nicolò-Laptop")).isEqualTo("Nicolò");
    }

    @Test
    void genericAndDefaultNamesGiveNobody() {
        assertThat(name("DESKTOP-AB12CD3")).isNull();
        assertThat(name("LAPTOP-IMNTQ2FH")).isNull();
        assertThat(name("Android_JF8NGDTE")).isNull();
        assertThat(name("Android-3")).isNull();
        assertThat(name("iPhone")).isNull();
        assertThat(name("Admin-PC")).isNull();
        assertThat(name("Sala-PC")).isNull();
        assertThat(name("PC-Ufficio")).isNull();
        assertThat(name("MacBook-Pro")).isNull();
        assertThat(name("iPad-di-casa")).isNull();
        assertThat(name("Stanza-di-Marco")).isNull();          // no device word before "di"
        assertThat(name("iPhone-di-Marco-Rossi-2")).isNull();  // not only name words after "di"
        assertThat(name("LGwebOSTV")).isNull();
        assertThat(name(null)).isNull();
        assertThat(name(" ")).isNull();
    }
}
