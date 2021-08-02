package com.github.peacetrue.sample.oss.oidc;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

/**
 * @author : xiayx
 * @since : 2021-07-29 08:08
 **/
@Slf4j
@Controller
public class IndexController {

    @GetMapping({"/index", "/"})
    public String index(Model model, Principal principal,
                        @RegisteredOAuth2AuthorizedClient("oidc-sp") OAuth2AuthorizedClient authorizedClient) {
        log.info("用户[{}]进入首页", principal.getName());
        model.addAttribute("user", principal);
        return "/index";
    }

}
