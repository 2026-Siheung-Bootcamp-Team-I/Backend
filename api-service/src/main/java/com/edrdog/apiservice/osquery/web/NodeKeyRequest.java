package com.edrdog.apiservice.osquery.web;

import com.fasterxml.jackson.annotation.JsonProperty;

/** config 요청 등 node_key 만 담는 요청. */
public record NodeKeyRequest(
        @JsonProperty("node_key") String nodeKey
) {
}
