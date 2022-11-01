package com.security.core.user;

import com.security.domain.Usuario;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;
import java.util.Collections;

@Getter
public class AuthUser extends User {
    
    private static final long serialVersionUID = 1L;
    
    private String fullName;
    
    public AuthUser(Usuario usuario) {
        super(usuario.getEmail(), usuario.getSenha(), Collections.emptyList());
        
        this.fullName = usuario.getNome();
    }
    
}
