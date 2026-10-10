package com.scanner.demo;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface TrackedTargetRepository extends JpaRepository<TrackedTarget, Long> {
    
    TrackedTarget findByTargetNameAndTargetType(String targetName, String targetType);

    List<TrackedTarget> findByAutoScheduleTrue();
}
