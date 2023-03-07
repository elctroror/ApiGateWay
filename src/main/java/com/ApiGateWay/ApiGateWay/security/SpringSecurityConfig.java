package com.ApiGateWay.ApiGateWay.security;


import io.netty.resolver.DefaultAddressResolverGroup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.netty.http.client.HttpClient;


@EnableWebFluxSecurity
public class SpringSecurityConfig {

    @Autowired
    private JwtAuthenticationFilter authenticationFilter;

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) {
        return http.authorizeExchange()
                .pathMatchers("/api/security/oauth/token", "/api/users/user/listName/**").permitAll()
                .pathMatchers("**").hasAnyRole("admin")
                /*.pathMatchers("/api/accounts/account/**").hasAnyRole("admin")
                .pathMatchers("/api/transactions/transaction/**").hasAnyRole("admin")
                .pathMatchers("/api/mails/mail/**").hasAnyRole("admin")
                .pathMatchers("/api/accounts/account/**").hasAnyRole("admin")
                .pathMatchers("/api/users/user/**").hasAnyRole("admin")*/
                .anyExchange().authenticated()
                .and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf().disable()
                .build();
    }
    @Bean
    public HttpClient httpClient(){
        return HttpClient.create().resolver(DefaultAddressResolverGroup.INSTANCE);
    }
}
