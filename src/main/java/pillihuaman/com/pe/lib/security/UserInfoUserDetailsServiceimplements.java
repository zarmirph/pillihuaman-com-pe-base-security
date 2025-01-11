package pillihuaman.com.pe.lib.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pillihuaman.com.pe.basebd.user.User;
import pillihuaman.com.pe.basebd.user.dao.UserRepository;

import java.util.Optional;
@Service
public class UserInfoUserDetailsServiceimplements implements UserDetailsService {

    private final UserRepository repository;

    public UserInfoUserDetailsServiceimplements(UserRepository repository) {
        this.repository = repository;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            Optional<User> userInfo = repository.findByEmail(username);
            return userInfo.orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

            //return userInfo.map(User::new)
              //      .orElseThrow(() -> new UsernameNotFoundException("user not found " + username));
        }
        catch (Exception ex){
            throw  ex;
        }

    }
}
