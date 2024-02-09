package org.techlab.labxpert.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@CrossOrigin("*")
@RestController
@RequestMapping("/api/test")
public class TestController {
    @GetMapping("/public")
    public String allAccess() {
        return "Public Content.";
    }

    @GetMapping("/private")
    public String userAccess() {
        return "Technicien Content.";
    }
}
