package org.techlab.labxpert.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.techlab.labxpert.entity.User;
import org.techlab.labxpert.entity.Utilisateur;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}
