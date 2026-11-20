package com.shsc.people;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.people.PeopleService.PersonView;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * People of a home and their devices (docs/05-API.md §People, M24). {@code devices} lists the
 * PROBABLE (automatic, with source and evidence) and CONFIRMED associations; removed ones are
 * not shown and are never proposed again.
 */
@RestController
public class PeopleController {

    public record PersonRequest(@NotNull @Size(max = 200) String name) {
    }

    public record AssignmentResponse(UUID deviceId, String status, String source, String evidence,
            Instant updatedAt) {
    }

    public record PersonResponse(UUID id, UUID homeId, String name, String origin, Instant createdAt,
            List<AssignmentResponse> devices) {
        static PersonResponse of(PersonView v) {
            return new PersonResponse(v.person().id(), v.person().homeId(), v.person().name(), v.person().origin(),
                    v.person().createdAt(), v.devices().stream().map(a -> new AssignmentResponse(a.deviceId(),
                            a.status(), a.source(), a.evidence(), a.updatedAt())).toList());
        }
    }

    private final PeopleService service;

    public PeopleController(PeopleService service) {
        this.service = service;
    }

    @GetMapping("/api/v1/homes/{homeId}/people")
    public List<PersonResponse> list(@PathVariable UUID homeId) {
        return service.list(homeId).stream().map(PersonResponse::of).toList();
    }

    @PostMapping("/api/v1/homes/{homeId}/people")
    @ResponseStatus(HttpStatus.CREATED)
    public PersonResponse create(@PathVariable UUID homeId, @Valid @RequestBody PersonRequest request,
            HttpServletRequest http) {
        return PersonResponse.of(service.create(homeId, request.name(), ClientInfo.from(http)));
    }

    @PutMapping("/api/v1/people/{personId}")
    public PersonResponse rename(@PathVariable UUID personId, @Valid @RequestBody PersonRequest request,
            HttpServletRequest http) {
        return PersonResponse.of(service.rename(personId, request.name(), ClientInfo.from(http)));
    }

    @DeleteMapping("/api/v1/people/{personId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID personId, HttpServletRequest http) {
        service.delete(personId, ClientInfo.from(http));
    }

    /** Assigns the device to the person, or confirms a probable association. */
    @PutMapping("/api/v1/devices/{deviceId}/people/{personId}")
    public PersonResponse assign(@PathVariable UUID deviceId, @PathVariable UUID personId, HttpServletRequest http) {
        return PersonResponse.of(service.assign(deviceId, personId, ClientInfo.from(http)));
    }

    /** Removes the association: automatic sources do not propose it again. */
    @DeleteMapping("/api/v1/devices/{deviceId}/people/{personId}")
    public PersonResponse unassign(@PathVariable UUID deviceId, @PathVariable UUID personId,
            HttpServletRequest http) {
        return PersonResponse.of(service.unassign(deviceId, personId, ClientInfo.from(http)));
    }
}
