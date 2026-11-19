package com.shsc.overview;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.overview.OverviewService.HomeOverview;

/** Dashboard overview: the visible homes with score, counted findings, devices and last scan (docs/05-API.md). */
@RestController
public class OverviewController {

    private final OverviewService service;

    public OverviewController(OverviewService service) {
        this.service = service;
    }

    @GetMapping("/api/v1/overview")
    public List<HomeOverview> overview() {
        return service.overview();
    }
}
