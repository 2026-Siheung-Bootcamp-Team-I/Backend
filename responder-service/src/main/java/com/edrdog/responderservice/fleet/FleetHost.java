package com.edrdog.responderservice.fleet;

/**
 * Fleet 호스트 조회 결과 중 조치에 필요한 것만.
 *
 * @param id       Fleet 내부 host id (스크립트 실행 대상 지정에 쓴다)
 * @param platform Fleet 이 보고하는 플랫폼(windows / darwin / ubuntu ...).
 *                 Fleet 은 Windows 에 PowerShell, 그 외에 sh 를 실행하므로 스크립트를 이 값으로 고른다.
 */
public record FleetHost(int id, String platform) {
}
