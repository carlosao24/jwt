package com.krakedev.jwt.service;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entity.Usuario;
import com.krakedev.jwt.repository.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }


    public Usuario guardar(Usuario usuario) {
    	
    	String contraseñaAutenticada = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());
    	
    	usuario.setPassword(contraseñaAutenticada);
    	
        return usuarioRepository.save(usuario);
    }


    public boolean autenticar(String username, String password) {
        Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(username);

        if (usuarioOpt.isPresent()) {
            Usuario usuario = usuarioOpt.get();
            if (BCrypt.checkpw(password, usuario.getPassword())) {
                return true;
            }
        }
        
        return false;
    }
}