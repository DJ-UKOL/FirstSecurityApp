package ru.dinerik.springcourse.FirstSecurityApp.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;

// Класс для работы с JWT Токенами
// Генерируем и отдаем клиенту и валидируем принятый от клиента токен
@Component
public class JWTUtil {

    @Value("${jwt_secret}")     // Выносим ключ в файл properties
    private String secret;

    // Создаем токен для пользователя.
    public String generateToken(String username) {
        Date expirationDate = Date.from(ZonedDateTime.now().plusMinutes(60).toInstant());  // Срок годности токена
        return JWT.create()         // Создаем JWT токен
                .withSubject("User details")      // Поле, где храниться данные пользователя
                .withClaim("username", username)              // Помещаем пары ключ-значение
                .withIssuedAt(new Date())                           // Указываем когда этот токен был выдан
                .withIssuer("dinerik")                              // Указываем кто выдал данный токен
                .withExpiresAt(expirationDate)                     // Указываем когда срок действия токена
                .sign(Algorithm.HMAC256(secret));    // Подписываем и указываем секретный ключ.
    }

    // Проверяем токен который получили от пользователя
    public String validateTokenAndRetrieveClaim(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))       // Создаем валидатор
                .withSubject("User details")
                .withIssuer("dinerik")
                .build();
        DecodedJWT jwt = verifier.verify(token);        // Валидируем токен и получаем декодированный jwt
        return jwt.getClaim("username").asString();  // Получим имя пользователя
    }
}
