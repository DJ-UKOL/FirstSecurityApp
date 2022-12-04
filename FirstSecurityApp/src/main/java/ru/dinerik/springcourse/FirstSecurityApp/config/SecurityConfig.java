package ru.dinerik.springcourse.FirstSecurityApp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import ru.dinerik.springcourse.FirstSecurityApp.services.PersonDetailService;

// Все что относится к Spring Security настраивается в этом классе
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)  // Для указания роли пользователю
public class SecurityConfig {

    private final PersonDetailService personDetailService;

    @Autowired
    public SecurityConfig(PersonDetailService personDetailService) {
        this.personDetailService = personDetailService;
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
                //.csrf().disable()                     // Отключить защиту от межсайтовой подделки запросов
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
        ;
        http.authenticationProvider(authenticationProvider());
        return http.build();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}