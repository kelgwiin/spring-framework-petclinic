package org.springframework.samples.petclinic.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(value = "/admin")
public class AdminController {
    @RequestMapping(value = "/home", method = RequestMethod.GET)
    public String showHome(ModelMap model) {
        return "admin/adminArea";
    }

}
