package com.dieggoh.sbjwt.repositories;

import com.dieggoh.sbjwt.models.ERole;
import com.dieggoh.sbjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
