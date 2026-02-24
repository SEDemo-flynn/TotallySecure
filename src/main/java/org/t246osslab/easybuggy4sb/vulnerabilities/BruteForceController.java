package org.t246osslab.easybuggy4sb.vulnerabilities;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import org.t246osslab.easybuggy4sb.Config;
import org.t246osslab.easybuggy4sb.controller.DefaultLoginController;

@Controller
public class BruteForceController extends DefaultLoginController {

    @Override
    @RequestMapping(value = Config.APP_ROOT + "/bruteforce/login", method = RequestMethod.GET)
    public ModelAndView doGet(ModelAndView mav, HttpServletRequest req, HttpServletResponse res, Locale locale) {
        req.setAttribute("note", msg.getMessage("msg.note.brute.force", null, locale));
        super.doGet(mav, req, res, locale);
        return mav;
    }

    @Override
    @RequestMapping(value = Config.APP_ROOT + "/bruteforce/login", method = RequestMethod.POST)
    public ModelAndView doPost(ModelAndView mav, HttpServletRequest req, HttpServletResponse res, Locale locale)
            throws IOException {

        String userid = req.getParameter("userid");
        String password = req.getParameter("password");

        HttpSession session = req.getSession(true);
        if (authUser(userid, password)) {
            session.setAttribute("authNMsg", "authenticated");
            session.setAttribute("userid", userid);

            String target = (String) session.getAttribute("target");
            if (target == null) {
                res.sendRedirect(res.encodeRedirectURL(Config.APP_ROOT + "/admins/main"));
            } else {
                session.removeAttribute("target");
                // Validate URL to prevent open redirect vulnerability
                if (isValidRedirectUrl(target)) {
                    res.sendRedirect(res.encodeRedirectURL(target));
                } else {
                    // Fallback to safe default if validation fails
                    res.sendRedirect(res.encodeRedirectURL(Config.APP_ROOT + "/admins/main"));
                }
            }
            return null;
        } else {
            session.setAttribute("authNMsg", msg.getMessage("msg.authentication.fail", null, locale));
        }
        return doGet(mav, req, res, locale);
    }

    /**
     * Validates redirect URL to prevent open redirect vulnerabilities.
     * Only allows relative URLs or URLs within the application root.
     * @param url The URL to validate
     * @return true if the URL is safe to redirect to, false otherwise
     */
    private boolean isValidRedirectUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        // Allow only relative URLs (starting with / but not //)
        if (url.startsWith("/") && !url.startsWith("//")) {
            return true;
        }
        
        // Reject absolute URLs to prevent open redirect
        return false;
    }
}
