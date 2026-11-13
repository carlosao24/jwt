package com.krakedev.jwt.controller;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.krakedev.jwt.JwtUtil;
import com.krakedev.jwt.entity.Usuario;
import com.krakedev.jwt.repository.UsuarioRepository;
import com.krakedev.jwt.service.TokenBlackListService;
import com.krakedev.jwt.service.UsuarioService;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private final UsuarioService serviceUser;
	private final UsuarioRepository repoUser;
	private final TokenBlackListService blackListService;

	public AuthController(UsuarioService serviceUser, UsuarioRepository repoUser,
			TokenBlackListService blackListService) {
		this.serviceUser = serviceUser;
		this.repoUser = repoUser;
		this.blackListService = blackListService;
	}

	@PostMapping("/registrar")
	public ResponseEntity<?> registrar(@RequestBody Usuario user) {
		try {
			Usuario userNuevo = serviceUser.guardar(user);
			return ResponseEntity.status(HttpStatus.CREATED).body(userNuevo);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al registrar usuario");
		}
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {

		String username = credenciales.get("username");

		String password = credenciales.get("password");

		boolean autenticado = serviceUser.autenticar(username, password);

		if (autenticado) {
			Usuario userObt = repoUser.findByUsername(username).get();
			String token = JwtUtil.generarToken(userObt.getUsername(), userObt.getRol());
			return ResponseEntity.ok(Map.of("token", token));

		} else {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autorizado");
		}
	}

	@GetMapping("/perfil")
	public ResponseEntity<?> verPerfil() {

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		String usuario = auth.getName();

		String rol = auth.getAuthorities().iterator().next().getAuthority();

		return ResponseEntity.ok(Map.of("Mensaje", "Bienvenido al sistema protegido por Spring Security", "Usuario",
				usuario, "rol_detectado", rol, "status", "Autenticado exitosamente"));

	}

	@PostMapping("/logout")
	public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
		if (authHeader != null && authHeader.startsWith("Bearer ")) {

			String token = authHeader.substring(7);

			blackListService.invalidarToken(token);

			return ResponseEntity.ok(Map.of("Mensaje", "Sesion cerrada exitosamente. Token invalido"));

		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token no proporcionado");
		}
	}
	
	
	@GetMapping("/dashboard")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> adminDashboard(){
		
		String usuario = SecurityContextHolder.getContext().getAuthentication().getName();
		
		return ResponseEntity.ok(Map.of("Mensaje", "Bienvenido al panel secreto de administradores", "admin", usuario));
		
	}

}
