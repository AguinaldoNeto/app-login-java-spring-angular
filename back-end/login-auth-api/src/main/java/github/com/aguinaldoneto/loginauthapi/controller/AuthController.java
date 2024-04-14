package github.com.aguinaldoneto.loginauthapi.controller;

import github.com.aguinaldoneto.loginauthapi.domain.user.User;
import github.com.aguinaldoneto.loginauthapi.dto.LoginRequestDTO;
import github.com.aguinaldoneto.loginauthapi.dto.RegisterRequestDTO;
import github.com.aguinaldoneto.loginauthapi.dto.ResponseDTO;
import github.com.aguinaldoneto.loginauthapi.infra.security.TokenService;
import github.com.aguinaldoneto.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
//lombok vai criar os construtores necessários
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body) {
        User user = repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found"));

        //primeiro passa a senha descriptografada, depois a senha criptografada
        if (passwordEncoder.matches(body.password(), user.getPassword())) {
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }

        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body) {
        Optional<User> user = repository.findByEmail(body.email());

        if (user.isEmpty()) {
            User newUser = new User();
            newUser.setName(body.name());
            newUser.setEmail(body.email());
            //vai criptograr a senha no BD;
            newUser.setPassword(passwordEncoder.encode(body.password()));

            this.repository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));
        }

        return ResponseEntity.badRequest().build();
    }

}
