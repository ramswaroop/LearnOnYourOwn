package todoapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import todoapp.models.User;
import todoapp.repositories.UserRepository;
import todoapp.services.CurrentUserDetailsService;

@SpringBootApplication
public class TodoApplication  {
     
    public static void main(String[] args) {
        SpringApplication.run(TodoApplication.class, args);
           
    }

    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        CurrentUserDetailsService currentUserDetailsService;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/", "/vendor/**", "/app/**", "/assets/**").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .httpBasic();
        }

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(currentUserDetailsService);
        }
    }
}
