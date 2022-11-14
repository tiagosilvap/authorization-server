package com.security.core.mfa;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class MfaService {

    private static final Map<String, String> SECRET_BY_USERNAME = Map.of("tiago@gmail.com", "JBSWY3DPEHPK3PXP");
    
//    private static final Map<String, String> SECRET_BY_USERNAME =
//            Stream.of(new String[][] {
//                    {"tiago@gmail.com", "JBSWY3DPEHPK3PXP"}, {"maria.vnd@algafood.com.br", "JBSWY3DPEHPK3PXP"},
//            }).collect(Collectors.collectingAndThen(
//                    Collectors.toMap(data -> data[0], data -> data[1]),
//                    Collections::<String, String> unmodifiableMap));
    
    private GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
    
    public boolean isEnabled(String username) {
        return SECRET_BY_USERNAME.containsKey(username);
    }
    
    public boolean verifyCode(String username, int code) {
        return code == googleAuthenticator.getTotpPassword(SECRET_BY_USERNAME.get(username));
    }

}
