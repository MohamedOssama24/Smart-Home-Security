package com.shsc.customers;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.customers.CustomerRepository.Customer;
import com.shsc.customers.CustomerRepository.CustomerData;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Customers of the organization (B2B). Archiving replaces deletion. */
@RestController
@RequestMapping("/api/v1/customers")
public class CustomerController {

    /** Full replacement of the editable fields (omitted optional fields are cleared). */
    public record CustomerRequest(
            @NotBlank @Size(max = 200) String displayName,
            @Email @Size(max = 254) String contactEmail,
            @Pattern(regexp = "^$|^[+0-9 ()./-]{4,30}$") String contactPhone,
            @Size(max = 1000) String notes) {

        CustomerData data() {
            return new CustomerData(displayName, contactEmail, contactPhone, notes);
        }
    }

    public record CustomerResponse(UUID id, String displayName, String contactEmail, String contactPhone,
            String notes, Instant createdAt, Instant updatedAt) {
        static CustomerResponse of(Customer c) {
            return new CustomerResponse(c.id(), c.displayName(), c.contactEmail(), c.contactPhone(), c.notes(),
                    c.createdAt(), c.updatedAt());
        }
    }

    private final CustomerService customers;

    public CustomerController(CustomerService customers) {
        this.customers = customers;
    }

    @PostMapping
    public ResponseEntity<CustomerResponse> create(@Valid @RequestBody CustomerRequest request,
            HttpServletRequest http) {
        Customer customer = customers.create(request.data(), ClientInfo.from(http));
        return ResponseEntity.created(URI.create("/api/v1/customers/" + customer.id()))
                .body(CustomerResponse.of(customer));
    }

    @GetMapping
    public List<CustomerResponse> list() {
        return customers.list().stream().map(CustomerResponse::of).toList();
    }

    @GetMapping("/{customerId}")
    public CustomerResponse get(@PathVariable UUID customerId) {
        return CustomerResponse.of(customers.get(customerId));
    }

    @PutMapping("/{customerId}")
    public CustomerResponse update(@PathVariable UUID customerId, @Valid @RequestBody CustomerRequest request,
            HttpServletRequest http) {
        return CustomerResponse.of(customers.update(customerId, request.data(), ClientInfo.from(http)));
    }

    @DeleteMapping("/{customerId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void archive(@PathVariable UUID customerId, HttpServletRequest http) {
        customers.archive(customerId, ClientInfo.from(http));
    }
}
