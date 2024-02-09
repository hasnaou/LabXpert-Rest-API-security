package org.techlab.labxpert.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.techlab.labxpert.security.jwt.AuthEntryPointJwt;
import org.techlab.labxpert.security.jwt.AuthTokenFilter;
import org.techlab.labxpert.security.services.UserDetailsServiceImpl;
import org.springframework.http.HttpMethod;

import static org.techlab.labxpert.Enum.ERole.*;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth ->{
                    auth.antMatchers("/api/auth/**").permitAll();

                    auth.antMatchers(HttpMethod.GET, "/api/v1/patient/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/patient").hasAnyRole("PREVELEUR");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/patient/**").hasAnyRole("PREVELEUR");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/patient/**").hasAnyRole("PREVELEUR");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/analyse/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/analyse").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/analyse/**").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/analyse/**").hasAnyRole("TECHNICIEN");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/echantillon/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/echantillon").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/echantillon/**").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/echantillon/**").hasAnyRole("TECHNICIEN");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/fournisseur/**").hasAnyRole("RESPONSABLE");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/fournisseur").hasAnyRole("RESPONSABLE");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/fournisseur/**").hasAnyRole("RESPONSABLE");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/fournisseur/**").hasAnyRole("RESPONSABLE");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/norme/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/norme").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/norme/**").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/norme/**").hasAnyRole("TECHNICIEN");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/numeration/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/numeration").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/numeration/**").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/numeration/**").hasAnyRole("TECHNICIEN");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/outil/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/outil").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/outil/**").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/outil/**").hasAnyRole("TECHNICIEN");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/Reactif/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/Reactif").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/Reactif/**").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/Reactif/**").hasAnyRole("TECHNICIEN");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/test/**").hasAnyRole("PREVELEUR", "TECHNICIEN");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/test").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/test/**").hasAnyRole("TECHNICIEN");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/test/**").hasAnyRole("TECHNICIEN");

                    auth.antMatchers(HttpMethod.GET, "/api/v1/utilisateur/**").hasAnyRole("RESPONSABLE");
                    auth.antMatchers(HttpMethod.POST, "/api/v1/utilisateur").hasAnyRole("RESPONSABLE");
                    auth.antMatchers(HttpMethod.PUT, "/api/v1/utilisateur/**").hasAnyRole("RESPONSABLE");
                    auth.antMatchers(HttpMethod.DELETE, "/api/v1/utilisateur/**").hasAnyRole("RESPONSABLE");

                    auth.anyRequest().authenticated();
                }
        );

        http.authenticationProvider(authenticationProvider());

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
