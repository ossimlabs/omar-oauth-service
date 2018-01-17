package io.ossim.omaroauthservice

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

import java.security.Principal

@EnableOAuth2Sso
@RestController
@SpringBootApplication
class OmarOauthServiceApplication extends WebSecurityConfigurerAdapter
{

    /**
     * Description: runs the OAuth Spring Boot Application
     *
     * @param args
     */
    static void main(String[] args)
    {
        SpringApplication.run OmarOauthServiceApplication, args
    }

    /**
     * Description: returns a JSON object with the OAuth token
     *
     * @param user
     * @return
     */
    @RequestMapping(name= '/token')
    static Map<String, String> token(Principal user)
    {
        OAuth2Authentication auth = (OAuth2Authentication) user

        return [token: auth.getDetails().getTokenValue()]
    }

    /**
     * Description: returns a JSON object with the name of the OAuth user
     *
     * @param user
     * @return
     */
    @RequestMapping('/user')
    static Map<String, String> user(Principal user)
    {
        return [user: user.name]
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .antMatcher("/**")
            .authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**")
                .permitAll()
            .anyRequest()
                .authenticated()
            .and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .and().csrf().disable();

    }
}
