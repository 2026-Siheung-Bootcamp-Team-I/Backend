package com.edrdog.apiservice.demo;

import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 시드 순서 계약. 계정 시드가 tenant 를 확보하지 못하면 데이터 시드도 멈춰야 한다.
 * 예전에 둘을 각각 ApplicationRunner 로 두어, 남의 조직이 tenant PK 를 쓰고 있는데도
 * 데모 alert 가 그 조직에 적재된 적이 있다.
 */
class DemoSeederTest {

    @Test
    void tenant_확보에_실패하면_데이터를_넣지_않는다() {
        DemoAccountSeeder account = mock(DemoAccountSeeder.class);
        DemoDataSeeder data = mock(DemoDataSeeder.class);
        when(account.seed()).thenReturn(false);

        new DemoSeeder(account, data).run(null);

        verify(data, never()).seed();
    }

    @Test
    void tenant_를_확보하면_데이터도_넣는다() {
        DemoAccountSeeder account = mock(DemoAccountSeeder.class);
        DemoDataSeeder data = mock(DemoDataSeeder.class);
        when(account.seed()).thenReturn(true);

        new DemoSeeder(account, data).run(null);

        verify(data).seed();
    }
}
