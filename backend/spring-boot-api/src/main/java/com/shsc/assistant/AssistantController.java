package com.shsc.assistant;

import java.util.UUID;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.assistant.AssistantService.Answer;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** AI security assistant: questions about one home, read-only (docs/05-API.md §Assistant). */
@RestController
public class AssistantController {

    public record QuestionRequest(
            @NotBlank @Size(max = 500) @Pattern(regexp = "[^\\p{Cntrl}]*(\\n[^\\p{Cntrl}]*)*")
            String question,
            @Pattern(regexp = "it|en") String locale) {
    }

    private final AssistantService service;

    public AssistantController(AssistantService service) {
        this.service = service;
    }

    @PostMapping("/api/v1/homes/{homeId}/assistant/questions")
    public Answer ask(@PathVariable UUID homeId, @Valid @RequestBody QuestionRequest request,
            HttpServletRequest http) {
        return service.ask(homeId, request.question().strip(), request.locale(), ClientInfo.from(http));
    }
}
