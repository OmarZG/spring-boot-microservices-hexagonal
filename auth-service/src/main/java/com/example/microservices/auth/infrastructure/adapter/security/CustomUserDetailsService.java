package com.example.microservices.auth.infrastructure.adapter.security;

import com.example.microservices.auth.application.adapter.UserDetailsAdapter;
import com.example.microservices.auth.domain.model.User;
import com.example.microservices.auth.domain.port.out.UserPort;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Custom UserDetailsService implementation
 * Loads user from database and adapts to Spring Security UserDetails
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserPort userPort;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userPort.findByUsername(username)
                .or(() -> userPort.findByEmail(username))
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + username));

        return new UserDetailsAdapter(user);
    }
}
