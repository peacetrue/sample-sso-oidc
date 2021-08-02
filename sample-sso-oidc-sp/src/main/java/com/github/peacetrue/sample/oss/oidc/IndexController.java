package com.github.peacetrue.sample.oss.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.security.Principal;

import static com.github.peacetrue.sample.oss.oidc.SpOidcApplication.REGISTRATION_ID;

/**
 * @author : xiayx
 * @since : 2021-07-29 08:08
 **/
@Slf4j
@Controller
public class IndexController {

    @Autowired
    private ObjectMapper objectMapper;

    @GetMapping({"/", "/index"})
    public String index(Model model) {
        log.info("进入首页");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("isLogined", !(authentication instanceof AnonymousAuthenticationToken));
        model.addAttribute("user", authentication);
        model.addAttribute("authorizationRequestUri", SpOidcApplication.getAuthorizationRequestUri());
        return "/index";
    }

    @GetMapping("/home")
    public String home(Model model,
                       Principal principal,
                       @RegisteredOAuth2AuthorizedClient(REGISTRATION_ID) OAuth2AuthorizedClient authorizedClient
    ) throws IOException {
        log.info("用户[{}]进入主页", principal.getName());
        model.addAttribute("isLogined", true);
        model.addAttribute("user", principal);
        model.addAttribute("authorizedClient", objectMapper.writeValueAsString(authorizedClient));
        return "/index";
    }

}
