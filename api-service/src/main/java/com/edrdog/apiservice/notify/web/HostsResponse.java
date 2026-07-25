package com.edrdog.apiservice.notify.web;

import java.util.List;

/** 내가 소유한 host 목록 응답. */
public record HostsResponse(List<String> hosts) {
}
