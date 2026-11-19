package com.shsc.devices.oui;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.StringReader;

import org.junit.jupiter.api.Test;

import com.shsc.devices.oui.OuiRegistryParser.Entry;
import com.shsc.devices.oui.OuiRegistryParser.Result;

/** IEEE CSV format: header, quoted names with commas, other registries and bad rows skipped. [MOCK] rows. */
class OuiRegistryParserTest {

    @Test
    void parsesTheThreeRegistriesAndSkipsAnythingElse() throws Exception {
        String csv = """
                Registry,Assignment,Organization Name,Organization Address
                MA-L,0011AA,"MOCK Maker, Inc.","1 Mock Street, Testville IT"
                MA-L,0011ab,MOCK Lowercase Ltd,Somewhere
                MA-M,0011AA1,MOCK Medium Block,Somewhere
                MA-S,0011AA123,"MOCK ""Quoted"" Small","Line one
                line two"
                IAB,0050C2000,MOCK Old Block,Somewhere
                MA-L,0011A,MOCK Too Short,Somewhere
                MA-L,0011AG,MOCK Not Hex,Somewhere
                MA-L,0011AC,,Somewhere

                """;
        Result r = OuiRegistryParser.parse(new StringReader(csv));
        assertThat(r.entries()).containsExactly(
                new Entry("0011AA", 24, "MOCK Maker, Inc.", "MA-L"),
                new Entry("0011AB", 24, "MOCK Lowercase Ltd", "MA-L"),
                new Entry("0011AA1", 28, "MOCK Medium Block", "MA-M"),
                new Entry("0011AA123", 36, "MOCK \"Quoted\" Small", "MA-S"));
        assertThat(r.skipped()).isEqualTo(4);
    }
}
