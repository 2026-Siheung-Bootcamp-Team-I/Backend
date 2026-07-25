package com.edrdog.apiservice.notify.web;

import com.edrdog.apiservice.notify.SlackWebhookClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.client.ResourceAccessException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * POST /api/me/webhook/test 배선(Bearer 유저 해석, webhook 미등록 404, Slack 실제 발송, 오류 매핑)을 검증한다.
 * Slack 은 실제로 부르지 않고 SlackWebhookClient 를 목으로 대체한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class UserNotifyControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private SlackWebhookClient slackWebhookClient;

    private String signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        return om.readTree(res.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    void 등록된_webhook_없으면_404() throws Exception {
        String token = signup("no-webhook@edrdog.com");

        mvc.perform(post("/api/me/webhook/test").header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("등록된 webhook 이 없습니다"));

        verify(slackWebhookClient, never()).send(anyString(), anyString());
    }

    @Test
    void 저장된_webhook으로_발송하고_슬랙_상태코드를_돌려준다() throws Exception {
        String token = signup("has-webhook@edrdog.com");
        mvc.perform(put("/api/me/webhook")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"webhookUrl\":\"https://hooks.slack.com/services/x\"}"))
                .andExpect(status().isOk());
        when(slackWebhookClient.send(eq("https://hooks.slack.com/services/x"), anyString())).thenReturn(200);

        mvc.perform(post("/api/me/webhook/test").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.status").value(200));

        verify(slackWebhookClient).send(eq("https://hooks.slack.com/services/x"), anyString());
    }

    @Test
    void 슬랙이_오류를_주면_502() throws Exception {
        String token = signup("slack-error@edrdog.com");
        mvc.perform(put("/api/me/webhook")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"webhookUrl\":\"https://hooks.slack.com/services/x\"}"))
                .andExpect(status().isOk());
        when(slackWebhookClient.send(anyString(), anyString())).thenReturn(404);

        mvc.perform(post("/api/me/webhook/test").header("Authorization", "Bearer " + token))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void 연결_실패면_502() throws Exception {
        String token = signup("slack-timeout@edrdog.com");
        mvc.perform(put("/api/me/webhook")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"webhookUrl\":\"https://hooks.slack.com/services/x\"}"))
                .andExpect(status().isOk());
        when(slackWebhookClient.send(anyString(), anyString()))
                .thenThrow(new ResourceAccessException("timeout"));

        mvc.perform(post("/api/me/webhook/test").header("Authorization", "Bearer " + token))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(post("/api/me/webhook/test")).andExpect(status().isUnauthorized());
    }
}
