package com.example.demo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private TokenProvider tokenProvider;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            //요청에서 토큰 가져오기
            String token=parseBearerToken(request);
            log.info("Filter is running...");

            //토큰 검사하기. JWT이므로 인가 서버에 요청하지 않고도 검증 가능
            if(token!=null && !token.equalsIgnoreCase("null")){
                //userID가져오기. 위조된 경우는 예외처리 된다.
                String userID=tokenProvider.validateAndGetUserId(token);
                log.info("Authenticated user ID: "+userID);

                //인증 완료. SecurityContextHolder에 등록해야 인증된 사용자라고 생각한다.
                AbstractAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(
                        userID, //인증된 사용자의 정보. 문자열이 아니어도 아무거나 넣을 수 있다. 보통 UserDetails라는 오브젝트를 넣는데
                                //우리는 넣지 않았다.
                        null,
                        AuthorityUtils.NO_AUTHORITIES
                );

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //SecurityContext 생성
                SecurityContext securityContext= SecurityContextHolder.createEmptyContext();
                //생성한 컨텍스트에 인증 정보인 authentication 넣고
                //이유: 요청 처리 과정에서 사용자의 인증 여부나 인증된 사용자가 누군지 알아야 할 때가 있기 때문이다.
                securityContext.setAuthentication(authenticationToken);
                //다시 SecurityContextHolder에 컨텍스트로 등록하는 것이다.
                //ThreadLocal에 저장돼서 스레드마다 하나의 컨텍스트를 관리하고
                //같은 스레드 내라면 어디에서든 접근할 수 있다.
                SecurityContextHolder.setContext(securityContext);

            }
        }catch(Exception ex){
            logger.error("Could not set user authentication in security context",ex);
        }

        filterChain.doFilter(request,response);
    }

    private String parseBearerToken(HttpServletRequest request) {
        //HTTP 요청의 헤더를 파싱해 Bearer 토큰을 리턴한다
        String bearerToken=request.getHeader("Authorization");

        if(StringUtils.hasText(bearerToken)&& bearerToken.startsWith("Bearer")){
            return bearerToken.substring(7);
        }
        return null;
    }
}
