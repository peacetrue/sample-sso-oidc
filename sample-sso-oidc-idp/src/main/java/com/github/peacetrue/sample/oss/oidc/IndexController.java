package com.github.peacetrue.sample.oss.oidc;

import lombok.extern.slf4j.Slf4j;
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

    @GetMapping({"/", "/index"})
    public String index(Model model, Principal principal) {
        log.info("用户[{}]进入首页", principal.getName());
        model.addAttribute("user", principal);
        // use index not /index
        //see https://stackoverflow.com/questions/45803546/thymeleaf-spring-boot-error-resolving-template
        // https://github.com/spring-projects/spring-boot/issues/1744
//        return "/index";
        return "index";
    }

}
