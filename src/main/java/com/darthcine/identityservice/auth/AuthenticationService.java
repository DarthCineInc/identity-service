package com.darthcine.identityservice.auth;

import com.darthcine.identityservice.config.JwtService;
import com.darthcine.identityservice.user.Role;
import com.darthcine.identityservice.user.User;
import com.darthcine.identityservice.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

@Service
@RequiredArgsConstructor
@Validated
public class AuthenticationService
{
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request)
    {
        try {
            var user = User.builder()
                    .name(request.getName())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(Role.CLIENT)
                    .build();
            repository.save(user);
            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        }
        catch(DataIntegrityViolationException e) {
            throw new RuntimeException("Register Violation");
        }
    }

    public AuthenticationResponse login(LoginRequest request)
    {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public Boolean TokenAuthentication(TokenAuthenticationRequest request)
    {
        try {
            var jwtToken = request.getCurrentToken();
            String username = jwtService.extractUsername(jwtToken);
            var user = repository.findByEmail(username);
            if (user != null)
            {
                Boolean valid = jwtService.isTokenExpired(jwtToken);
                return !valid;
            }
            else
            {
                return false;
            }

        } catch (Exception e)
        {
        }
        return false;
    }
}
