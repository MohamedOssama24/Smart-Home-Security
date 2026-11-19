package com.shsc.billing;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.billing.BrandingService.Branding;
import com.shsc.billing.BrandingService.BrandingData;
import com.shsc.billing.BrandingService.Logo;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

/** White label of the current tenant (PRO plan). */
@RestController
public class BrandingController {

    public record BrandingRequest(@Size(max = 80) String displayName, @Size(max = 7) String primaryColor,
            @Email @Size(max = 254) String supportEmail) {
    }

    private final BrandingService branding;

    public BrandingController(BrandingService branding) {
        this.branding = branding;
    }

    @GetMapping("/api/v1/branding")
    public Branding current() {
        return branding.current();
    }

    @PutMapping("/api/v1/branding")
    public Branding update(@Valid @RequestBody BrandingRequest request, HttpServletRequest http) {
        return branding.update(new BrandingData(request.displayName(), request.primaryColor(), request.supportEmail()),
                ClientInfo.from(http));
    }

    @PutMapping(value = "/api/v1/branding/logo", consumes = { MediaType.IMAGE_PNG_VALUE, MediaType.IMAGE_JPEG_VALUE })
    public Branding uploadLogo(@RequestBody byte[] logo,
            @RequestHeader(HttpHeaders.CONTENT_TYPE) String contentType, HttpServletRequest http) {
        return branding.uploadLogo(logo, contentType, ClientInfo.from(http));
    }

    @DeleteMapping("/api/v1/branding/logo")
    public Branding deleteLogo(HttpServletRequest http) {
        return branding.deleteLogo(ClientInfo.from(http));
    }

    @GetMapping("/api/v1/branding/logo")
    public ResponseEntity<byte[]> logo() {
        Logo logo = branding.logo();
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(logo.contentType()))
                .cacheControl(CacheControl.noStore().cachePrivate())
                .header("X-Content-Type-Options", "nosniff")
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=logo")
                .header("Content-Security-Policy", "default-src 'none'; sandbox")
                .body(logo.bytes());
    }
}
