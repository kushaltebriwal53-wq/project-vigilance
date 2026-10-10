package com.scanner.demo;

import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/targets")
public class TrackedTargetController {

    private final TrackedTargetRepository trackedTargetRepository;

    public TrackedTargetController(TrackedTargetRepository trackedTargetRepository) {
        this.trackedTargetRepository = trackedTargetRepository;
    }

    @GetMapping("/active")
    public List<TrackedTarget> getActiveTargets() {
        return trackedTargetRepository.findByAutoScheduleTrue();
    }

    @PostMapping("/stop")
    public Map<String, String> stopTargetMonitoring(@RequestParam Long id) {
        return trackedTargetRepository.findById(id).map(target -> {
            target.autoSchedule = false;
            trackedTargetRepository.save(target);
            return Map.of("status", "SUCCESS", "message", "Monitoring stopped for: " + target.targetName);
        }).orElse(Map.of("status", "ERROR", "message", "Target not found"));
    }

    @PostMapping("/stop-by-name")
    public Map<String, String> stopTargetByName(@RequestParam String name) {
        List<TrackedTarget> targets = trackedTargetRepository.findAll();
        boolean found = false;
        for (TrackedTarget t : targets) {
            if (t.targetName != null && t.targetName.equalsIgnoreCase(name)) {
                t.autoSchedule = false;
                trackedTargetRepository.save(t);
                found = true;
            }
        }
        if (found) {
            return Map.of("status", "SUCCESS", "message", "Monitoring stopped for " + name);
        } else {
            return Map.of("status", "ERROR", "message", "No active target found with name " + name);
        }
    }
}
