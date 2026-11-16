package com.shsc.homes;

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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.homes.HomeRepository.Home;
import com.shsc.homes.HomeRepository.HomeData;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RestController
@RequestMapping("/api/v1/homes")
public class HomeController {

    /** Create, or full replacement of the editable fields (omitted optional fields are cleared). */
    public record HomeRequest(
            @NotBlank @Size(max = 100) String name,
            UUID customerId,
            @Size(max = 300) String address,
            @Size(max = 64) String timezone) {

        HomeData data() {
            return new HomeData(name, customerId, address, timezone);
        }
    }

    public record HomeResponse(UUID id, String name, UUID customerId, String address, String timezone,
            Instant createdAt, Instant updatedAt) {
        static HomeResponse of(Home home) {
            return new HomeResponse(home.id(), home.name(), home.customerId(), home.address(), home.timezone(),
                    home.createdAt(), home.updatedAt());
        }
    }

    private final HomeService homes;

    public HomeController(HomeService homes) {
        this.homes = homes;
    }

    @PostMapping
    public ResponseEntity<HomeResponse> create(@Valid @RequestBody HomeRequest request, HttpServletRequest http) {
        Home home = homes.create(request.data(), ClientInfo.from(http));
        return ResponseEntity.created(URI.create("/api/v1/homes/" + home.id())).body(HomeResponse.of(home));
    }

    @GetMapping
    public List<HomeResponse> list(@RequestParam(required = false) UUID customerId) {
        return homes.list(customerId).stream().map(HomeResponse::of).toList();
    }

    @GetMapping("/{homeId}")
    public HomeResponse get(@PathVariable UUID homeId) {
        return HomeResponse.of(homes.get(homeId));
    }

    @PutMapping("/{homeId}")
    public HomeResponse update(@PathVariable UUID homeId, @Valid @RequestBody HomeRequest request,
            HttpServletRequest http) {
        return HomeResponse.of(homes.update(homeId, request.data(), ClientInfo.from(http)));
    }

    /** Archives the home (soft delete: history and audit are kept). */
    @DeleteMapping("/{homeId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void archive(@PathVariable UUID homeId, HttpServletRequest http) {
        homes.archive(homeId, ClientInfo.from(http));
    }
}
