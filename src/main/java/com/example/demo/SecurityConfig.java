package com.example.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.filter.CharacterEncodingFilter;

import static org.hibernate.criterion.Restrictions.and;

//import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@Configuration
@EnableWebSecurity
//@EnableRedisHttpSession
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Profile("!OAuth")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private String[] ignoredMatcherPattern = { "/static/**", "/css/**", "/js/**", "/images/**", "/webjars/**", "/**/favicon.ico" };
    private String[] permitAllPattern = { "/", "/index", "/login", "/errorpage/**" };

    public static final String AUTHENTICATION_HEADER_NAME = "Authorization";
    public static final String AUTHENTICATION_URL = "/api/auth/login";
    public static final String REFRESH_TOKEN_URL = "/api/auth/token";
    public static final String API_ROOT_URL = "/api/**";

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private FormAuthenticationProvider commonAuthenticationProvider;
    @Autowired
    private FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private FormAuthenticationFailureHandler formAuthenticationFailureHandler;
    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;
    @Autowired
    private AccessDeniedHandler accessDeniedHandler;
//    @Autowired
//    private AccessDecisionManager accessDecisionManager;
//    @Autowired
//    private FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource;
//    @Autowired
//    private RememberMeServices rememberMeServices;
//    @Autowired
//    private ObjectMapper objectMapper;
//    @Autowired
//    private AuthenticationManagerBuilder authenticationManagerBuilder;

//    @Bean
//    @Override
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) {
//        auth.authenticationProvider(commonAuthenticationProvider);
//    }
//
//    public AuthenticationManager authenticationManager(){
//        List<AuthenticationProvider> authProviderList = new ArrayList<>();
//        authProviderList.add(commonAuthenticationProvider);
//        ProviderManager providerManager = new ProviderManager(authProviderList);
//        return providerManager;
//    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(ignoredMatcherPattern);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();
        http
            .authorizeRequests()
                .anyRequest().authenticated();
//        .and()
//                .csrf().disable();

//            .and()
//                .oauth2Login()
//                .failureHandler(oAuth2AuthenticationFailureHandler)
//                .successHandler(oAuth2AuthenticationSuccessHandler)
//                .defaultSuccessUrl("/loginSuccess")
//                .failureUrl("/loginFailure")
//
//            .and()
//                .headers().frameOptions().disable()

//            .and()
//                .exceptionHandling()
//                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                .accessDeniedPage("/denied")
//                .accessDeniedHandler(accessDeniedHandler)

//            .and()
//                .formLogin()
//                .loginPage("/login")
//                .loginProcessingUrl("/login_proc")
//                //.defaultSuccessUrl("/index")
//                .failureUrl("/login?error=true")
//                .usernameParameter("username")
//                .passwordParameter("password")
//                .successHandler(formAuthenticationSuccessHandler)
//                .failureHandler(formAuthenticationFailureHandler);
               // .authenticationDetailsSource(authenticationDetailsSource)

//            .and()
//                .sessionManagement()
//                .invalidSessionUrl("/users/invalidSession.html")
//                .maximumSessions(1) // -1 : 무제한 로그인 세션 허용
//                .maxSessionsPreventsLogin(true) // false : 동시 로그인을 하지 못하도록 차단함
//                .sessionRegistry(sessionRegistry()).and()
//                .sessionFixation().migrateSession()
//
//            .and()
//                .logout()
//                .logoutSuccessHandler(logoutSuccessHandler)
//                //.logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/index")
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("SESSION","JSESSIONID", "remember-me")
//
//            .and()
//                .rememberMe()
//                .rememberMeServices(rememberMeServices)
//                .tokenValiditySeconds(3600)
//                .key("anymobi")
//
//            .and()
//                .addFilterBefore(new CustomCorsFilter(), UsernamePasswordAuthenticationFilter.class)
////                .addFilterBefore(buildAjaxLoginProcessingFilter(AUTHENTICATION_URL), UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(buildJwtLoginProcessingFilter(REFRESH_TOKEN_URL), UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(filter, CsrfFilter.class)
//                .addFilterBefore(commonFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
//                .addFilterAfter(new CsrfHeaderFilter(), CsrfFilter.class)
//                .csrf().csrfTokenRepository(csrfTokenRepository()).disable();

            //customConfigurer(http);
    }

//    private void customConfigurer(HttpSecurity http) throws Exception {
//        http
//                .apply(new CommonConfigurer<>(authenticationManagerBuilder))
//
//            .and()
//                .apply(new AjaxLoginConfigurer<>())
//                .successHandlerAjax(ajaxAuthenticationSuccessHandler)
//                .failureHandlerAjax(ajaxAuthenticationFailureHandler)
//                .loginProcessingUrl(AUTHENTICATION_URL)
//                .setAuthenticationManager(ajaxAuthenticationManager())
//                .readAndWriteMapper(objectMapper);
//
//
//    }

//    protected AjaxLoginProcessingFilter buildAjaxLoginProcessingFilter(String loginEntryPoint){
//        AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter();
//        filter.setAuthenticationManager(ajaxAuthenticationManager());
//        return filter;
//    }

//    @Bean
//    public CommonFilterSecurityInterceptor commonFilterSecurityInterceptor(){
//        CommonFilterSecurityInterceptor commonFilterSecurityInterceptor = new CommonFilterSecurityInterceptor(permitAllPattern);
//        //commonFilterSecurityInterceptor.setAuthenticationManager(authenticationManager());
//        commonFilterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager);
//        commonFilterSecurityInterceptor.setSecurityMetadataSource(filterInvocationSecurityMetadataSource);
//        commonFilterSecurityInterceptor.setRejectPublicInvocations(false);
//        return commonFilterSecurityInterceptor;
//    }

//    private CsrfTokenRepository csrfTokenRepository() {
//        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
//        repository.setHeaderName("X-XSRF-TOKEN");
//        return repository;
//    }

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties oAuth2ClientProperties, @Value("${custom.oauth2.kakao.client-id}") String kakaoClientId) {
//        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().keySet().stream()
//                .map(client -> getRegistration(oAuth2ClientProperties, client))
//                .filter(Objects::nonNull)
//                .collect(Collectors.toList());
//
//        registrations.add(OAuth2Provider.KAKAO.getBuilder("kakao")
//                .clientId(kakaoClientId)
//                .clientSecret("test")
//                .jwkSetUri("test")
//                .build());
//
//        return new InMemoryClientRegistrationRepository(registrations);
//    }
//
//    private ClientRegistration getRegistration(OAuth2ClientProperties clientProperties, String client) {
//        if ("google".equals(client)) {
//            OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("google");
//            return org.springframework.security.config.oauth2.client.CommonOAuth2Provider.GOOGLE.getBuilder(client)
//                    .clientId(registration.getClientId())
//                    .clientSecret(registration.getClientSecret())
//                    .scope("email", "profile")
//                    .build();
//        }
//        if ("facebook".equals(client)) {
//            OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("facebook");
//            return org.springframework.security.config.oauth2.client.CommonOAuth2Provider.FACEBOOK.getBuilder(client)
//                    .clientId(registration.getClientId())
//                    .clientSecret(registration.getClientSecret())
//                    .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,link")
//                    .scope("email")
//                    .build();
//        }
//        return null;
//    }

//    @Bean
//    public FilterRegistrationBean filterRegistrationBean() {
//        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
//        filterRegistrationBean.setFilter(commonFilterSecurityInterceptor());
//        filterRegistrationBean.setEnabled(false);
//        return filterRegistrationBean;
//    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CommonAccessDeniedHandler commonAccessDeniedHandler = new CommonAccessDeniedHandler();
        commonAccessDeniedHandler.setErrorPage("/denied");
        return commonAccessDeniedHandler;
    }

//    @Bean
//    public RememberMeServices rememberMeServices(PersistentTokenRepository ptr) {
//        FormRememberMeServices rememberMeServices = new FormRememberMeServices("anymobi", userDetailsService, ptr);
//        return rememberMeServices;
//    }

//    @Bean
//    public PersistentTokenRepository persistentTokenRepository(RememberMeTokenRepository rmtr) {
//        return new JpaPersistentTokenRepository(rmtr);
//    }

//    @Bean
//    @Profile("affirmative")
//    public AffirmativeBased affirmativeBased() {
//        AffirmativeBased accessDecisionManager = new AffirmativeBased(getAccessDecisionVoters());
//        accessDecisionManager.setAllowIfAllAbstainDecisions(false); // 접근 승인 거부 보류시 접근 허용은 true 접근 거부는 false
//        return accessDecisionManager;
//    }

//    @Bean
//    @Profile("unanimous")
//    public UnanimousBased unanimousBased() {
//        UnanimousBased accessDecisionManager = new UnanimousBased(getAccessDecisionVoters());
//        accessDecisionManager.setAllowIfAllAbstainDecisions(false);
//        return accessDecisionManager;
//    }
//
//    @Bean
//    @Profile("consensus")
//    public ConsensusBased consensusBased() {
//        ConsensusBased accessDecisionManager = new ConsensusBased(getAccessDecisionVoters());
//        accessDecisionManager.setAllowIfAllAbstainDecisions(false);
//        return accessDecisionManager;
//    }

//    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
//
//        AuthenticatedVoter authenticatedVoter = new AuthenticatedVoter();
//        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
//        //IpAddressVoter ipAddressVoter = new IpAddressVoter();
//
//        List<AccessDecisionVoter<? extends Object>> accessDecisionVoterList = Arrays.asList(authenticatedVoter, webExpressionVoter,roleVoter());
//        return accessDecisionVoterList;
//    }
//
//    @Bean
//    public RoleHierarchyVoter roleVoter() {
//        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
//        roleHierarchyVoter.setRolePrefix("ROLE_");
//        return roleHierarchyVoter;
//    }
//
//    @Bean
//    public RoleHierarchyImpl roleHierarchy() {
//        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
//        return roleHierarchy;
//    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

//    @Bean
//    public TokenStore tokenStore() {
//        return new InMemoryTokenStore();
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

//    @Bean
//    public AbstractAuthenticationFilterConfigurer ajaxLoginConfigurer() {
//        AjaxLoginConfigurer<HttpSecurity> ajaxLoginConfigurer = new AjaxLoginConfigurer<>(objectMapper);
//        ajaxLoginConfigurer.successHandler(ajaxAuthenticationSuccessHandler).failureHandler(ajaxAuthenticationFailureHandler);
//        return ajaxLoginConfigurer;
//
//    }

}