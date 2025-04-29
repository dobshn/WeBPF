https://ebpf.io/what-is-ebpf/ 읽으며 정리한 글

- eBPF는 Linux 커널의 권한을 갖는 샌드박스 프로그램을 실행시킬 수 있는 기술
- 안전하고 효율적으로 커널의 기능 확장을 커널 소스코드 변경이나 모듈 로드 없이 할 수 있음

- 운영체제는 observation, security, networking functionality를 제공하기에 좋은 환경임
	- 커널의 특권 덕분에
- 하지만, 이렇게 중요한 역할을 하고 있으므로 변경하는 것이 쉽지 않음
- 따라서 OS의 발전 속도는 OS 외의 속도보다 느렸음

- eBPF는 런타임 중에 운영체제 안에서 샌드박스 프로그램을 실행할 수 있도록 함
- eBPF의 사용처
	- 고성능 네트워킹 및 로드 밸런싱
	- 낮은 오버헤드를 갖는 세밀한 보안 관찰
	- 애플리케이션 추적
	- 성능 문제 해결

**BPF**
- Berkeley Packet Filter의 줄임말
- eBPF는 extended BPF의 줄임말
	- 오늘날 eBPF는 packet filtering 외의 다양한 일을 할 수 있기 때문에, 약어가 그대로 유효하진 않음
- eBPF는 고유명사가 되었음
- 문서나 툴에서 다루는 BPF나 eBPF는 사실상 같은 의미
	- 과거의 진짜 BPF는 cBPF(classic BPF)라고 부름

- eBPF 프로그램은 이벤트가 발생했을 때 실행된다
	- system calls
	- function entry/exit
	- kernel tracepoints
	- network events
	- etc.

**Designated Initializer(지정 초기화자)**

```c
struct 타입 변수명 = {
	.멤버이름 = 값,
	...
}
```
- 멤버 이름 앞에 `.`을 붙임으로써 순서 상관 없이 값을 지정할 수 있다.

```c
#include <stdio.h>

struct person {
	int id;
	char name[20];
	int age;
};

int main(void)
{
	struct person p = {
		.name = "Name",
		.age = 20,
		.id = 110110
	};
	printf("id: %d\nname: %s\nage: %d\n", p.id, p.name, p.age);

	return 0;
}
```

출력 결과
```c
id: 110110
name: Name
age: 20
```

- **kprobe**: kernel probe
- **uprobe**: user probe
	- probe: 찔러본다는 뜻
		- 특정 지점을 감시하거나 개입하는 장치

- eBPF 코드는 바이트코드로 커널에 로딩된다
	- `bpftrace`와 같은 추상화 도구로 바이트코드를 커널에 로드하고 이벤트에 바인딩할 수 있다
	- 직접 코드를 작성할 경우 C로 작성 후 `clang`등으로 컴파일하여 바이트코드 생성

- 바이트코드로 생성된 eBPF 프로그램은 bpf 시스템 콜을 통해 리눅스 커널에 로드될 수 있음
	- 이는 일반적으로 eBPF 라이브러리 중 하나를 통해 수행됨
- eBPF 프로그램이 커널에 로드될 때, 후크에 연결되기 전에 두 단계를 거침
	- Verification
	- JIT Compilation

### Verification
eBPF 프로그램이 안전한지 검증하는 단계이다. 다음과 같은 조건들을 검사한다.
- eBPF 프로그램이 요구하는 권한을 프로세스가 가지고 있는지
- 시스템을 손상시키지 않는지
- 프로그램이 무한루프에 빠지지 않는지

### JIT Compilation
eBPF 프로그램의 바이트코드를 기계어로 번역한다. 이를 통해 eBPF 프로그램이 커널 네이티브 코드나 모듈과 같이 빠른 속도를 가질 수 있다.

### Maps
eBPF 프로그램은 수집한 정보와 상태를 map의 개념을 통해 프로그램 뿐만아니라 사용자 공간에도 공유할 수 있다. 사용자 공간에서는 시스템 콜을 통해 map에 접근할 수 있다.

### Helper Calls
eBPF 프로그램은 특정 커널 버전에 종속되지 않기 위해 커널 함수를 직접 호출하지 않는다. 대신, API인 헬퍼 함수들을 호출한다.

### Tail & Function Calls
eBPF 프로그램 내에서도 함수를 정의하고 호출할 수 있다. Tail Call은 하나의 eBPF 프로그램이 또 다른 eBPF 프로그램을 실행하는 것이다. (`evec()`와 유사)

### eBPF Safety

eBPF는 강력한 기능을 제공하는 만큼, 그에대한 안정성이 보장되어야 한다.

**Required Privileges**
eBPF를 로드하여 실행하려는 프로그램은 그에 맞는 권한을 가지고 있어야 한다.

**Verifier**
만약 프로세스가 eBPF 프로그램을 로드하기로 했다면, 프로그램은 eBPF verifier를 거친다. eBPF verifier는 eBPF 프로그램 자체를 검증한다.
- 프로그램이 무한 루프나 무한 block에 빠지지 않는지 검증한다.
- 초기화되지 않은 데이터를 사용하거나 메모리 바운드를 넘어 접근하지 않는지 검증한다.
- 프로그램의 크기가 시스템 요구사항에 맞는지 검증한다.
- 프로그램이 너무 복잡하지 않은지 검증한다. verifier는 가능한 모든 경로를 탐색한다.
verifier는 안전 검사이지, 보안 검사가 아니다. 프로그램이 어떤 작업을 수행하는지는 조사하지 않는다.

**Hardening**
- 프로그램 실행 보호:
	- 커널이 보유하게된 eBPF 프로그램은 읽기 전용이 된다. 어떠한 이유로든 eBPF 프로그램이 수정되려고 하면, 이를 허용하는 대신 크러시를 발생시킨다.
- Spectre 공격 예방:
- 상수 블라인딩:
	- 코드에 포함된 모든 상수는 JIT 스프레이 공격 방지를 위해 블라인딩됨

### Abstracted Runtime Context
eBPF 프로그램은 임의의 커널 메모리에 접근할 수 없다. 프로그램 내부 접근 외의 모든 외부 접근은 eBPF helper를 통해 이루어진다.

## Why eBPF?

### The Power of Programmability

웹은 단순한 HTML 문서였다. 하지만 JavaScript의 등장으로 프로그래머블한 앱이 되었다. 이처럼 고정된 리눅스 커널을 프로그래머블하게 하는 것이 eBPF다.

### eBPF's impact on the Linux Kernel

Linux kernel의 역할은 애플리케이션이 하드웨어를 사용할 수 있도록 시스템 콜이라는 API를 제공하는 것이다. 이를 위해 커널은 다양한 서브시스템과 계층 구조를 유지하며 역할을 분산한다. 각 서브시스템은 어느 정도 수준의 변경은 허용하지만, 그 이상의 수정이 필요한 경우 커널 자체의 수정이 필요했다.

기존에 커널을 수정하는 방법은 두 가지였다.
1. 커널 소스 코드 변경
2. 커널 모듈 작성

소스 코드를 변경하는 것은 커널 커뮤니티를 설득하고, 이것이 반영되기까지 긴 시간을 기다려야한다.

커널 모듈을 작성하는 것은 매 커널 버전마다 업데이트가 필요할 수 있고, 보안 경계가 약하다는 단점이 있다.

eBPF는 커널 소스 코드를 수정하거나 모듈을 작성하지 않아도 Linux kernel의 동작을 프로그래밍할 수 있게 한다.

### Development Toolchains

**bcc**
Python 프로그램이 eBPF 프로그램을 내장할 수 있도록 하는 프레임워크이다. Python 프로그램 내에서 eBPF 프로그램을 바이트 코드로 변환한 뒤, 이를 커널에 로드한다.

**bpftrace**
간단한 스크립트로 eBPF 프로그램을 작성하고 실행할 수 있다. 내부적으로 LLVM이 bpftrace 스크립트를 eBPF 바이트코드로 컴파일 한 뒤 커널에 attach한다.

**eBPF Go Library**
eBPF 바이트코드 프로그램을 Go 언어로 작성된 프로그램에서 로드, attach, map다루기 위한 라이브러리

**libbpf C/C++ Library**
eBPF 바이트코드를 커널에 로딩하고 attach하거나 map을 제어하는 C/C++용 표준 도구이다.