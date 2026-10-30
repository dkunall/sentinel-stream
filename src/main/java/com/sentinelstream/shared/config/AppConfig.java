package com.sentinelstream.shared.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SentinelProperties.class)
class AppConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
