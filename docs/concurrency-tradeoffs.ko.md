# 실행 경계와 병렬성: 가설, 실험, 선택

현재 구현은 **동일 agent의 실행은 하나씩 처리하고, 서로 독립적으로 등록된 agent끼리는 병렬 실행**한다. 잠긴 executor의 프로세스 생성 제한을 풀지 않았다. 호출별 자원 최소 권한, 이전 호출의 주소 공간 제거, 같은 agent의 위임 세대 교체를 유지하면 이 선택에는 처리량과 시작 비용이 따른다. 이 문서는 그 비용을 실제로 측정하며, 측정값을 무결함이나 무제한 확장성의 증거로 해석하지 않는다.

## 서로 다른 세 가지 제약

1. **커널 정책은 좁아지는 방향으로만 바뀐다.** Landlock을 적용한 스레드에 다른 규칙을 추가해도 기존 제한과 교집합을 이룬다. A 파일만 읽도록 잠근 실행체를 B 파일만 읽는 실행체로 되돌려 쓸 수 없다. `exec`도 기존 Landlock 제한을 제거하는 수단이 아니다. [Linux Landlock 공식 문서](https://docs.kernel.org/userspace-api/landlock.html#layers-of-file-path-access-rights)
2. **현재 권한 모델은 agent당 실행 한 개다.** Provider의 `one_execution_per_agent`와 `one_live_grant_per_agent` 인덱스가 강제한다. SQLite 트랜잭션은 입장과 완료를 기록할 때만 유지하며 실제 HTTP 응답을 기다리는 동안에는 유지하지 않는다. 이 직렬화 범위는 코드가 선택한 보장이다. Landlock이 시스템 전체 병렬성을 금지해서 생긴 현상은 아니다.
3. **호출마다 깨끗한 주소 공간을 만든다.** trusted coordinator가 자식을 만든 뒤 sealed memfd의 고정 executor로 `execveat`한다. 핸들러는 주소 공간 교체와 Landlock/seccomp 설치 후에만 실행된다. executor 내부의 `fork`, `clone`, `exec`는 계속 금지한다. 단순 `fork`는 부모 메모리를 상속하고, `execve`는 스택·힙·데이터 영역을 새 이미지로 교체한다. [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html), [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)

따라서 현재 구조는 이미 호출마다 새 executor를 사용하는 Worker Cycling이다. 제한된 executor가 자식을 만드는 구조가 아니라, 제한을 설치하기 전의 신뢰된 coordinator가 생성과 회수를 담당한다. 시스템 전체에 `pids.max=1`처럼 자식 자체를 만들 수 없는 별도 제한이 있다면 이 구조는 시작할 수 없다. 지원하지 않는 환경에서 격리를 생략하는 대안은 제공하지 않는다.

## 검증할 가설

| 가설 | 판정할 실제 관찰 |
| --- | --- |
| H1. 규칙을 추가하면 A 전용 실행체를 B 전용으로 바꿀 수 있다 | 별도 자식에 A 규칙 적용 후 A/B 열기, 이어서 B 규칙 적용 후 A/B 열기 |
| H2. 같은 agent에 coordinator를 둘 띄우면 병렬 실행된다 | 첫 HTTP 핸들러를 실행 중에 두고 두 번째 coordinator의 입장 결과와 서버 진입 횟수 확인 |
| H3. 프로세스 생성 제한 때문에 다른 agent도 병렬 실행할 수 없다 | 서로 다른 인증서로 등록한 Alice와 Bob의 HTTP 처리 구간이 실제 겹치는지 확인 |
| H4. fork 비용이 호출 비용의 대부분이어서 cycling은 사용할 수 없다 | 장수 C++ coordinator 내부에서 직접 읽기, fork 제어군, exec 제어군, 생산 sandbox 호출, 전체 Provider 호출을 따로 측정 |
| H5. 부모 메모리 크기와 관계없이 비용이 같다 | coordinator의 추가 상주 메모리를 0/64/256 MiB로 바꿔 반복 |

H1에서는 A만 적용했을 때 A는 성공하고 B는 거절되며, B 규칙을 추가하면 **A와 B가 모두 거절**됐다. 생산 sandbox의 별도 probe에서도 허용 파일만 읽을 수 있고 `fork`와 `exec`는 `EPERM`이었다. 이 실험은 정책 교집합과 현재 필터의 동작을 검사한다. 임의의 커널 취약점이 없음을 증명하지는 않는다.

H2에서는 모든 회차에서 두 번째 호출이 `execution_busy`, `executor_started=false`로 끝났다. 서버 진입은 한 번뿐이었다. H3에서는 두 agent의 서버 처리 구간이 실제로 겹쳤다. 프로세스 풀이나 worker 수만 늘려도 H2의 논리적 gate는 바뀌지 않는다는 결론이다.

## 재현 방법과 측정 범위

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --target saga-worker saga-cycle-benchmark -j 4
.venv/bin/python -m experiments.tradeoffs
.venv/bin/python -m pytest -q tests/test_concurrency.py
```

`experiments/tradeoffs.py`는 임시 CA·인증서·Provider DB·4 KiB 파일·loopback HTTP 서버를 생성하고 모두 정리한다. 개인 자격 증명이나 외부 데이터셋을 사용하지 않는다. 결과는 `.artifacts/concurrency-tradeoffs.json`에 원시 샘플, 바이너리 SHA-256, 환경, cleanup 결과와 함께 저장된다. 파일은 실행할 때 생성하며 배포 패키지의 보장값이 아니다.

메커니즘 측정은 모드마다 **하나의 장수 C++ 프로세스** 안에서 warmup 20회 후 200회 측정한다. coordinator CLI의 시작과 fixture 생성은 샘플에서 제외한다. 전체 경로도 `Worker` 하나를 200회 재사용하되, state/권한 요청·mTLS·서명 검증·새 executor·완료 기록을 포함한다. 통계는 nearest-rank p50/p95이며 원시값을 보존한다. `fork_only`는 자식 생성·4 KiB 읽기·종료·회수의 합이며 `fork()` 시스템 호출만을 잰 값이 아니다. `fork_exec_control`은 sandbox를 적용하지 않고 **진단 ELF 전체**를 다시 exec하는 신뢰된 제어군이다. 생산 executor와 적재 DSO가 다르므로 두 수치를 빼서 순수 sandbox 비용을 계산하면 안 된다. 이 제어군은 생산 API에서 접근할 수 없다.

아래 값은 operation 재조정 경로까지 통합한 **2026-10-19 04:41 UTC 빌드**의 [보존한 원시 결과](benchmarks/concurrency-tradeoffs-20261019.json)다. [04:37 UTC 초기 기준](benchmarks/concurrency-tradeoffs-baseline-20261019.json)도 변동 비교를 위해 남겼다. 두 JSON은 각 바이너리 SHA-256을 기록하며 임시 경로나 인증서·키를 포함하지 않는다. 초기 기준은 operation 경로 통합 전이고, 아래 최종 기준은 통합 후다. 두 빌드 모두 메커니즘 샘플에는 CLI 시작 비용이 없다. Linux 7.1.5, Landlock ABI 9 이상, x86-64, Intel i7-10700 2.90 GHz, 논리 CPU 16개, Python 3.14.6, Release 빌드다. 다른 검증 작업이 동시에 실행 중이었고 load average는 시작 8.84, 종료 6.28이었다. 전용 머신의 최적 수치로 일반화하지 않는다.

| 경로 | 부모 추가 메모리 | p50 ms | p95 ms | 관측 평균 calls/s |
| --- | ---: | ---: | ---: | ---: |
| 직접 읽기 | 0 MiB | 0.0011 | 0.0012 | 827,390 |
| fork·읽기·회수, 신뢰된 제어군 | 0 MiB | 0.265 | 0.395 | 3,568 |
| fork·진단 ELF exec·읽기·회수, 신뢰된 제어군 | 0 MiB | 3.970 | 5.723 | 237.8 |
| 생산 sandbox, 빈 probe | 0 MiB | 11.934 | 12.724 | 83.1 |
| 생산 sandbox, 4 KiB 읽기 | 0 MiB | 12.029 | 13.324 | 81.9 |
| fork·읽기·회수, 신뢰된 제어군 | 64 MiB | 0.283 | 0.406 | 3,292 |
| 생산 sandbox, 4 KiB 읽기 | 64 MiB | 12.042 | 12.737 | 82.2 |
| fork·읽기·회수, 신뢰된 제어군 | 256 MiB | 7.538 | 10.166 | 129.7 |
| 생산 sandbox, 4 KiB 읽기 | 256 MiB | 19.600 | 22.420 | 50.2 |
| 실제 mTLS·Provider·sandbox·완료 전체 | 0 MiB | 37.864 | 46.497 | 25.9 |

모든 경로를 같은 의미의 비용으로 취급하면 안 된다. 직접 읽기와 제어군은 격리·권한 검증·영속 기록을 제공하지 않는다. 위 결과에서 **작은 coordinator의 fork 제어군 0.265 ms는 전체 경로 37.864 ms의 주된 항목이 아니었다**. 그러나 256 MiB 부모에서는 fork 제어군 p50이 7.538 ms까지 올라갔다. 초기 기준의 같은 크기 측정은 0.450 ms였고 생산 sandbox는 12.463 ms였다. 최종 기준은 각각 7.538 ms와 19.600 ms다. 부모 크기와 실행 시점에 따른 큰 변동을 숨겨서 fork 비용이 항상 작다고 결론 내릴 수 없다. 두 실행 사이의 다른 부하·메모리 배치·페이지 상태를 통제하지 않았으므로 변동 원인을 특정하지 않는다. 부모 주소 공간이 커지면 page table 등의 복제 비용이 달라질 수 있다는 가설과는 일치한다. Linux의 copy-on-write는 부모 메모리 전체를 즉시 물리 복사하는 방식이 아니다. [fork(2)의 구현 설명](https://man7.org/linux/man-pages/man2/fork.2.html#NOTES)

현재 생산 실행 경로에는 결과 파이프가 닫힌 직후 자식이 아직 종료되지 않았으면 `waitpid(WNOHANG)` 뒤 10 ms 대기하는 코드가 있다. 약 12 ms의 고정 시작 비용 중 이 회수 대기가 기여할 수 있다는 것은 코드와 측정에서 얻은 **추론**이다. 이 실험은 각 syscall의 시간을 추적하지 않았으므로 10 ms 전부를 정확히 분리 측정했다고 주장하지 않는다.

메모리는 coordinator RSS와 `RUSAGE_CHILDREN.ru_maxrss`를 기록한다. 예를 들어 0 MiB 생산 읽기 coordinator RSS는 약 8.0 MiB, 자식 lifetime 최대 RSS는 약 4.3 MiB였고, 부모 추가 256 MiB에서는 약 264 MiB와 259 MiB였다. **자식 최대 RSS는 exec 전 상속 구간과 warmup을 포함한다. COW 공유 페이지도 각 프로세스 RSS에 잡히므로 두 값을 합쳐 실제 물리 메모리 비용으로 삼을 수 없다.** 실행 후 executor의 정상 상태 RSS나 PSS, 최대 동시 프로세스 수에 따른 메모리 확장은 별도 측정이 필요하다. 512 MiB `RLIMIT_AS` 역시 실제 사용량이 아니라 주소 공간 상한이다.

250 ms 지연 자원에 대한 12회 측정은 다음과 같다. 이 표의 경과 시간은 두 coordinator의 전체 생명주기를 포함한다. 최종 측정은 첫 핸들러를 같은 agent의 경쟁 요청이 거절될 때까지 붙잡고, 독립 agent 두 개는 둘 다 진입한 뒤 함께 풀어 준다. 250 ms 지연은 release 후 시작한다. 병렬성 여부는 별도로 서버 안의 시작·종료 시각으로 확인했다. 초기 기준은 고정 지연만 사용했으며 그 원시 결과와 동기화 방식이 구별된다.

| 시나리오 | 결과 | p50 ms | p95 ms |
| --- | --- | ---: | ---: |
| 같은 agent의 동시 두 호출 | 성공 1 + gate 거절 1 | 315.2 | 326.5 |
| 독립 agent 두 개의 동시 호출 | 성공 2 | 327.3 | 338.9 |
| 독립 agent 두 개의 순차 호출 | 성공 2 | 588.5 | 607.9 |
| 독립 agent 핸들러끼리 실제 겹친 구간 | 모든 회차에서 양수 | 250.3 | 250.5 |

12개 샘플의 nearest-rank p95는 그 표본의 최댓값이다. H2의 시간은 작업 두 개를 처리한 시간이 아니므로 성공 두 개 시나리오와 처리량으로 비교하지 않는다. H3은 독립 agent 두 개의 overlap만 증명하며 수백 개 agent에 대한 선형 확장을 주장하지 않는다.

## 피할 수 없는 관계와 적용 방안

agent `a`의 gate가 admission commit부터 finish commit까지 `G_a`초 점유된다고 하자. 현재 불변식은 `active(a) ≤ 1`이다. 정상적으로 계속 완료되는 부하에서 agent당 장기 처리량의 상한은 대략 `1 / E[G_a]`다. 입장 전 네트워크·서명·DB 비용도 있으므로 실제 전체 처리량은 이보다 작을 수 있다. 동일 agent에 동시 요청을 늘려도 상한은 늘지 않는다. 대기열을 두면 거절을 순서대로 처리하는 형태로 바꿀 수 있지만, 작업 자체가 빨라지지는 않으며 현재 라이브러리는 묵시적 대기열을 제공하지 않는다.

독립적으로 승인된 agent가 N개라면 각자의 gate에서 실행할 수 있다. 총 처리량에는 `sum(1/E[G_a])` 외에 CPU, 파일 I/O, 원격 서비스, Provider의 짧은 SQLite 쓰기 직렬화가 상한으로 작용한다. 같은 파일을 쓰는 agent끼리의 업무 충돌까지 이 라이브러리가 해결하는 것은 아니다. 같은 주체를 이름만 여러 개로 복제하면 회수와 권한의 의미가 바뀌므로 자동으로 identity를 분할하지 않는다.

| 선택 | 얻는 것 | 반드시 치르는 것 | 현재 상태 |
| --- | --- | --- | --- |
| 동일 agent 순차 처리 + 현재 fresh executor | 단일 회수/세대 범위, 호출별 최소 권한과 주소 공간 교체 | 긴 작업이 후속 작업을 막음, 매 호출 생성·exec·정책 설치 | 기본 구현 |
| 사용자가 별도로 등록·승인한 독립 agent에 분배 | executor 제한 유지하며 독립 업무 병렬화 | 자격 증명과 정책 분리, agent별 회수, 공유 자원 충돌 관리 | 실제 실행으로 확인 |
| 명시적인 agent 내부 lane | 한 agent 이름 아래 여러 독립 실행 범위 | `(agent,lane)`별 generation/gate, agent 전체 회수 시 모든 lane fence 및 실행 중 작업 처리의 새 계약 | 설계 대안, 미구현 |
| 한 번도 핸들러를 실행하지 않은 깨끗한 일회용 executor 준비 풀 | 생성·exec 일부를 요청 이전으로 이동 가능 | 대기 프로세스 메모리·보충 비용·죽은 항목 처리·요청 바인딩 프로토콜, 총 작업량의 생성 비용은 남음 | 설계 대안, 미구현 |
| 신뢰된 전용 작은 forkserver | 큰 agent 프로세스의 page table 복제 비용 회피 가능 | 별도 신뢰 경계/IPC, 자격 증명 분리, 수명·장애 처리 | 설계 대안, 미구현 |
| 실행했던 executor 재사용 | 시작 비용 일부 절감 | 메모리 잔류, 바뀐 자원에 대해 이전 Landlock을 넓힐 수 없음 | 현재 요구와 양립하지 않아 미채택 |

풀을 추가해도 Provider가 같은 agent의 다음 admission을 거절하는 사실은 달라지지 않는다. 고정된 sandbox에 여러 자원의 권한 합집합을 미리 주고 재사용하면 최소 권한과 이전 호출 데이터 제거 보장이 달라진다. 모든 목표를 그대로 유지하면서 같은 agent의 임의 작업을 무제한 병렬 처리하는 해법은 없다. 현재 선택은 **동일 agent는 직렬화하고, 독립적으로 승인할 수 있는 업무는 별도 agent로 배치하며, 측정한 호출 비용이 허용되지 않는 업무에는 요구 보장의 변경 여부를 먼저 결정하는 것**이다.

타임아웃이 발생해 실행 종료를 확인할 수 없으면 gate가 남을 수 있다. 시간이 흘렀다는 이유로 gate를 풀면 이전 효과와 후속 효과가 겹칠 수 있으므로 자동 lease 만료로 가용성을 회복하지 않는다. 재시도는 같은 operation identity에 대한 상태 조회·완료 결과 재사용 계약을 따라야 하며, 새 identity 발급은 중복 효과를 안전하게 지워 주지 않는다.

참조한 [gsiros/saga](https://github.com/gsiros/saga)는 Provider와 agent, 설치 가능한 Python 라이브러리 및 예제를 제공한다. 이 저장소는 그와 같은 사용 가능한 배포 구조를 목표로 하지만, 위 실행 경계·Landlock·로컬 자원 실행의 비용을 upstream의 성능 보장으로 대신하지 않는다. 이 문서의 수치는 이 저장소의 실험 결과다.
