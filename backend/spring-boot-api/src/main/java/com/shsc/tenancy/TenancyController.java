package com.shsc.tenancy;

import java.time.Instant;
import java.util.UUID;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits.Plan;
import com.shsc.tenancy.PlanLimits.Usage;
import com.shsc.tenancy.TenancyService.TenantOverview;
import com.shsc.tenancy.TenantRepository.Organization;
import com.shsc.tenancy.TenantRepository.OrganizationData;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Current tenant with plan limits and usage; organization details of a BUSINESS tenant. */
@RestController
public class TenancyController {

    public record PlanResponse(String code, Integer maxHomes, Integer maxUsers, Integer maxCustomers,
            Integer maxNetworksPerHome) {
        static PlanResponse of(Plan plan) {
            return new PlanResponse(plan.code(), plan.maxHomes(), plan.maxUsers(), plan.maxCustomers(),
                    plan.maxNetworksPerHome());
        }
    }

    public record TenantResponse(UUID id, String type, String name, String status, UUID organizationId,
            PlanResponse plan, Usage usage) {
    }

    public record OrganizationResponse(UUID id, String legalName, String vatNumber, String contactEmail,
            String contactPhone, Instant createdAt, Instant updatedAt) {
        static OrganizationResponse of(Organization o) {
            return new OrganizationResponse(o.id(), o.legalName(), o.vatNumber(), o.contactEmail(), o.contactPhone(),
                    o.createdAt(), o.updatedAt());
        }
    }

    /** Full replacement of the editable fields (omitted optional fields are cleared). */
    public record OrganizationRequest(
            @NotBlank @Size(max = 200) String legalName,
            @Pattern(regexp = "^[A-Za-z0-9 ]{0,24}$") String vatNumber,
            @Email @Size(max = 254) String contactEmail,
            @Pattern(regexp = "^$|^[+0-9 ()./-]{4,30}$") String contactPhone) {
    }

    private final TenancyService tenancy;

    public TenancyController(TenancyService tenancy) {
        this.tenancy = tenancy;
    }

    @GetMapping("/api/v1/tenants/current")
    public TenantResponse tenant() {
        TenantOverview overview = tenancy.current();
        var t = overview.tenant();
        return new TenantResponse(t.id(), t.type().name(), t.name(), t.status(), t.organizationId(),
                PlanResponse.of(overview.plan()), overview.usage());
    }

    @GetMapping("/api/v1/organizations/current")
    public OrganizationResponse organization() {
        return OrganizationResponse.of(tenancy.organization());
    }

    @PutMapping("/api/v1/organizations/current")
    public OrganizationResponse updateOrganization(@Valid @RequestBody OrganizationRequest request,
            HttpServletRequest http) {
        return OrganizationResponse.of(tenancy.updateOrganization(new OrganizationData(request.legalName(),
                request.vatNumber(), request.contactEmail(), request.contactPhone()), ClientInfo.from(http)));
    }
}
