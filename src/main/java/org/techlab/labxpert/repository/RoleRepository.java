package org.techlab.labxpert.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.techlab.labxpert.Enum.ERole;
import org.techlab.labxpert.Enum.RoleUser;
import org.techlab.labxpert.entity.Role;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
