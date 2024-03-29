package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

import java.util.Locale;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private MessageSource messageSource;

    public WebConfig() {
        super();
    }

    @Override
    public void addViewControllers(final ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("home");
        registry.addViewController("/users/login.html");
        registry.addViewController("/users/loginRememberMe.html");
        registry.addViewController("/users/customLogin.html");
        registry.addViewController("/users/registration.html");
        registry.addViewController("/users/registrationCaptcha.html");
        registry.addViewController("/users/logout.html");
        registry.addViewController("/users/expiredAccount.html");
        registry.addViewController("/users/badUser.html");
        registry.addViewController("/users/emailError.html");
        registry.addViewController("/home.html");
        registry.addViewController("/users/invalidSession.html");
        registry.addViewController("/users/console.html");
        registry.addViewController("/admin/admin.html");
        registry.addViewController("/users/successRegister.html");
        registry.addViewController("/users/forgetPassword.html");
        registry.addViewController("/users/updatePassword.html");
        registry.addViewController("/users/changePassword.html");
        registry.addViewController("/users/users.html");
        registry.addViewController("/users/qrcode.html");
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
        lci.setParamName("lang");
        return lci;
    }

    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }

    @Bean
    public LocaleResolver localeResolver() {

        CookieLocaleResolver cookieLocaleResolver = new CookieLocaleResolver();
        cookieLocaleResolver.setDefaultLocale(Locale.KOREA);
        return cookieLocaleResolver;
    }

    @Override
    public Validator getValidator() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.setValidationMessageSource(messageSource);
        return validator;
    }

}
