package org.tron.walletcli;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.converter.DefaultContentTypeResolver;
import org.springframework.messaging.converter.MessageConverter;
import org.springframework.messaging.handler.invocation.HandlerMethodReturnValueHandler;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketTransportRegistration;
import org.springframework.web.socket.server.standard.TomcatRequestUpgradeStrategy;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;

import java.util.List;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
    @Override
    public void configureMessageBroker(MessageBrokerRegistry c){
        c.enableSimpleBroker("/persist");
        c.setApplicationDestinationPrefixes("/persist");
    }
    @Override
    public void registerStompEndpoints(StompEndpointRegistry reg){
        reg.addEndpoint("/walletws")
                //.setHandshakeHandler(new DefaultHandshakeHandler(new TomcatRequestUpgradeStrategy()))
                .setAllowedOrigins("*")
                .withSockJS();
    }
    @Override
    public void configureWebSocketTransport(WebSocketTransportRegistration reg){}

    @Override
    public void configureClientInboundChannel(ChannelRegistration reg){

    }

    @Override
    public boolean configureMessageConverters(List<MessageConverter> clist){
        return true;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver>resolvers){}

    @Override
    public void configureClientOutboundChannel(ChannelRegistration reg){}

    @Override
    public void addReturnValueHandlers(List<HandlerMethodReturnValueHandler>rhandler){}
}
