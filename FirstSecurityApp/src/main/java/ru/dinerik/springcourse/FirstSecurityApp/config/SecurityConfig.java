package ru.dinerik.springcourse.FirstSecurityApp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.dinerik.springcourse.FirstSecurityApp.services.PersonDetailService;

// Все что относится к Spring Security настраивается в этом классе
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)  // Для указания роли пользователю
public class SecurityConfig {

    private final PersonDetailService personDetailService;
    private final JWTFilter jwtFilter;


    @Autowired
    public SecurityConfig(PersonDetailService personDetailService, JWTFilter jwtFilter) {
        this.personDetailService = personDetailService;
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(personDetailService);
        authProvider.setPasswordEncoder(getPasswordEncoder());

        return authProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http        // правила авторизации
                .csrf().disable()                     // Отключить защиту от межсайтовой подделки запросов, т.к. мы используем jwt
                .authorizeRequests()                    // Конфигурируем запрос авторизации
                // .antMatchers("/admin").hasRole("ADMIN") // Ограничение для роли ROLE_ADMIN
                .antMatchers("/auth/login", "/auth/registration" ,"/error").permitAll() // Смотрим какой запрос пришел, пускаем по указанным страницам...
                //.anyRequest().authenticated()           // по другим адресам не пускаем неавторизированного пользователя
                .anyRequest().hasAnyRole("USER", "ADMIN")
                .and()                                  // перейти к настройке логина
                .formLogin()
                .loginPage("/auth/login")               // Указываем свою страницу для ввода логина
                .loginProcessingUrl("/process_login")   // Указываем куда отправлять данные с формы
                .defaultSuccessUrl("/hello", true)            // Действие после успешной авторизации
                .failureUrl("/auth/login?error")                   // Действие после ошибки
                .and()
                .logout()                                        // Разлогирование
                .logoutUrl("/logout")                            // Адрес по которому будет происходить ралогирование
                .logoutSuccessUrl("/auth/login")                              // Переход при успешном разлогировании
                .and()
                .sessionManagement()                    // Не сохранять сессию на нашем сервере
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        ;
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);        // Фильтр помогающий производить аутентификацию
        http.authenticationProvider(authenticationProvider());
        return http.build();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}