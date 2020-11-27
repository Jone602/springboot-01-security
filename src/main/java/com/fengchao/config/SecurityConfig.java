package com.fengchao.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    //授权
    protected void configure(HttpSecurity http) throws Exception {
        //只有首页所有人都可以访问，其他页面只有有权限的人才可以访问
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasAnyRole("vip1")
                .antMatchers("/level2/**").hasAnyRole("vip2")
                .antMatchers("/level3/**").hasAnyRole("vip3");
        //没有权限会默认跳转登录页 Login页面
        http.formLogin();
        //设置登录页面
        http.formLogin().loginPage("/toLogin");
        http.csrf().disable();//关闭csrf功能 跨站攻击
        //注销 注销成功后，跳转到 首页，并清除cook信息
        http.logout().logoutSuccessUrl("/");
        http.rememberMe().rememberMeParameter("rember");//记住我功能，cookie,默认保存两周时间14天,自定义记住我功能
    }
    //认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //目前是从内容中读取的用户信息，正常应该从 数据库中读取
        //密码以明文方式未加密报错，需要进行密码加密 BCryptPasswordEncoder()
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("fengchao").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");

    }
}
