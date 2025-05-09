실제 C 코드는 어떤 과정을 거쳐 BPF 바이트코드가 될까?

예시 코드 `prog.c`
```c
// prog.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx) {
    bpf_printk("Hello, exec!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```
- [[`SEC()`]] 매크를 통해 이 BPF 함수가 커널의 어떤 hook 지점에 attach될지를 정한다. 해당 프로그램에선 `sys_enter_execve`로, `execve` 시스템 콜의 진입 지점에 후킹된다.
- `trace_exec`는 함수의 이름으로, 사용자가 임의로 지정할 수 있다.
- `void *ctx` context에 대한 포인터로, attach 대상에 따라 다른 구조체가 들어온다.
- `char LICENSE[] SEC("license") = "GPL";`은 [[ELF]] 바이너리의 "license"라는 섹션에 "GPL"이라는 문자열을 추가한다.

## 1단계: C -> LLVM IR (.ll)

```bash
clang -S -emit-llvm -target bpf -O2 -g -c prog.c -o prog.ll
```
- `-S`: 어셈블리어가 아닌 소스로 출력(LLVM IR)
- `-emit-llvm`: LLVM IR 코드로 출력
- `-target bpf`: 컴파일 대상은 bpf 코드
- `-02`: 최적화 수준
- `-g`: 디버그 정보 포함
- `-c`: 링크하지 않고 컴파일만 진행
- `-o prog.ll`: 출력 파일 이름 지정

중간 컴파일이 완료된 `prog.ll` 파일의 내용은 다음과 같다.

```
; ModuleID = 'prog.c'
source_filename = "prog.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

@__const.trace_exec.____fmt = private unnamed_addr constant [14 x i8] c"Hello, exec!\0A\00", align 1
@LICENSE = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !0
@llvm.compiler.used = appending global [2 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @LICENSE, i32 0, i32 0), i8* bitcast (i32 (i8*)* @trace_exec to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @trace_exec(i8* nocapture readnone %0) #0 section "tracepoint/syscalls/sys_enter_execve" !dbg !26 {
  %2 = alloca [14 x i8], align 1
  call void @llvm.dbg.value(metadata i8* undef, metadata !32, metadata !DIExpression()), !dbg !38
  %3 = getelementptr inbounds [14 x i8], [14 x i8]* %2, i64 0, i64 0, !dbg !39
  call void @llvm.lifetime.start.p0i8(i64 14, i8* nonnull %3) #5, !dbg !39
  call void @llvm.dbg.declare(metadata [14 x i8]* %2, metadata !33, metadata !DIExpression()), !dbg !39
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(14) %3, i8* noundef nonnull align 1 dereferenceable(14) getelementptr inbounds ([14 x i8], [14 x i8]* @__const.trace_exec.____fmt, i64 0, i64 0), i64 14, i1 false), !dbg !39
  %4 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef nonnull %3, i32 noundef 14) #5, !dbg !39
  call void @llvm.lifetime.end.p0i8(i64 14, i8* nonnull %3) #5, !dbg !40
  ret i32 0, !dbg !41
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: argmemonly mustprogress nofree nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg) #3

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #4

attributes #0 = { nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { mustprogress nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { argmemonly mustprogress nofree nosync nounwind willreturn }
attributes #3 = { argmemonly mustprogress nofree nounwind willreturn }
attributes #4 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #5 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!21, !22, !23, !24}
!llvm.ident = !{!25}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", scope: !2, file: !3, line: 10, type: !18, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, globals: !4, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "prog.c", directory: "/home/seed/eBPF", checksumkind: CSK_MD5, checksum: "46f55d6038043f746614f161e5c74d6d")
!4 = !{!0, !5}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !7, line: 171, type: !8, isLocal: true, isDefinition: true)
!7 = !DIFile(filename: "/usr/include/bpf/bpf_helper_defs.h", directory: "", checksumkind: CSK_MD5, checksum: "eadf4a8bcf7ac4e7bd6d2cb666452242")
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DISubroutineType(types: !10)
!10 = !{!11, !12, !15, null}
!11 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !14)
!14 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!15 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !16, line: 27, baseType: !17)
!16 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "", checksumkind: CSK_MD5, checksum: "b810f270733e106319b67ef512c6246e")
!17 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!18 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 32, elements: !19)
!19 = !{!20}
!20 = !DISubrange(count: 4)
!21 = !{i32 7, !"Dwarf Version", i32 5}
!22 = !{i32 2, !"Debug Info Version", i32 3}
!23 = !{i32 1, !"wchar_size", i32 4}
!24 = !{i32 7, !"frame-pointer", i32 2}
!25 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!26 = distinct !DISubprogram(name: "trace_exec", scope: !3, file: !3, line: 5, type: !27, scopeLine: 5, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !31)
!27 = !DISubroutineType(types: !28)
!28 = !{!29, !30}
!29 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!31 = !{!32, !33}
!32 = !DILocalVariable(name: "ctx", arg: 1, scope: !26, file: !3, line: 5, type: !30)
!33 = !DILocalVariable(name: "____fmt", scope: !34, file: !3, line: 6, type: !35)
!34 = distinct !DILexicalBlock(scope: !26, file: !3, line: 6, column: 5)
!35 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 112, elements: !36)
!36 = !{!37}
!37 = !DISubrange(count: 14)
!38 = !DILocation(line: 0, scope: !26)
!39 = !DILocation(line: 6, column: 5, scope: !34)
!40 = !DILocation(line: 6, column: 5, scope: !26)
!41 = !DILocation(line: 7, column: 5, scope: !26)
```

# 2단계: LLVM IR -> eBPF ELF 오브젝트 (prog.o)

```bash
llc -march=bpf -filetype=obj prog.ll -o prog.o
```
- `-march=bpf`: BPF ISA로 컴파일 한다.
- `-filetype=obj`: ELF 오브젝트 파일로 출력한다.

결과물인 `prog.o`는 바이너리 파일로, 그냥 확인할 순 없다.
`readelf`라는 툴을 사용해 내용을 확인해보았다.

```bash
$ readelf -S prog.o
There are 25 section headers, starting at offset 0xb20:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .strtab           STRTAB           0000000000000000  00000a08
       0000000000000114  0000000000000000           0     0     1
  [ 2] .text             PROGBITS         0000000000000000  00000040
       0000000000000000  0000000000000000  AX       0     0     4
  [ 3] tracepoint/s[...] PROGBITS         0000000000000000  00000040
       0000000000000068  0000000000000000  AX       0     0     8
  [ 4] .rodata.str1.1    PROGBITS         0000000000000000  000000a8
       000000000000000e  0000000000000001 AMS       0     0     1
  [ 5] license           PROGBITS         0000000000000000  000000b6
       0000000000000004  0000000000000000  WA       0     0     1
  [ 6] .debug_abbrev     PROGBITS         0000000000000000  000000ba
       00000000000000cf  0000000000000000           0     0     1
  [ 7] .debug_info       PROGBITS         0000000000000000  00000189
       00000000000000b6  0000000000000000           0     0     1
  [ 8] .rel.debug_info   REL              0000000000000000  000007b8
       0000000000000050  0000000000000010   I      24     7     8
  [ 9] .debug_rnglists   PROGBITS         0000000000000000  0000023f
       0000000000000017  0000000000000000           0     0     1
  [10] .debug_str_o[...] PROGBITS         0000000000000000  00000256
       0000000000000040  0000000000000000           0     0     1
  [11] .rel.debug_s[...] REL              0000000000000000  00000808
       00000000000000e0  0000000000000010   I      24    10     8
  [12] .debug_str        PROGBITS         0000000000000000  00000296
       00000000000000a3  0000000000000001  MS       0     0     1
  [13] .debug_addr       PROGBITS         0000000000000000  00000339
       0000000000000018  0000000000000000           0     0     1
  [14] .rel.debug_addr   REL              0000000000000000  000008e8
       0000000000000020  0000000000000010   I      24    13     8
  [15] .BTF              PROGBITS         0000000000000000  00000354
       0000000000000179  0000000000000000           0     0     4
  [16] .rel.BTF          REL              0000000000000000  00000908
       0000000000000010  0000000000000010   I      24    15     8
  [17] .BTF.ext          PROGBITS         0000000000000000  000004d0
       0000000000000090  0000000000000000           0     0     4
  [18] .rel.BTF.ext      REL              0000000000000000  00000918
       0000000000000060  0000000000000010   I      24    17     8
  [19] .debug_frame      PROGBITS         0000000000000000  00000560
       0000000000000028  0000000000000000           0     0     8
  [20] .rel.debug_frame  REL              0000000000000000  00000978
       0000000000000020  0000000000000010   I      24    19     8
  [21] .debug_line       PROGBITS         0000000000000000  00000588
       0000000000000097  0000000000000000           0     0     1
  [22] .rel.debug_line   REL              0000000000000000  00000998
       0000000000000070  0000000000000010   I      24    21     8
  [23] .debug_line_str   PROGBITS         0000000000000000  0000061f
       000000000000005e  0000000000000001  MS       0     0     1
  [24] .symtab           SYMTAB           0000000000000000  00000680
       0000000000000138  0000000000000018           1    11     8
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)
readelf: Warning: unable to apply unsupported reloc type 3 to section .debug_info
readelf: Warning: Unrecognized form: 0x23
```

`tracepoint/s[...]`섹션, `license` 섹션이 존재함을 확인할 수 있다.

# 3단계: 커널에 attach

`libbpf` 라이브러리를 사용해 `prog.o` bpf 오브젝트 파일을 커널에 로드한다.

`main.c`
```c
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    // 1. BPF 오브젝트 열기
    obj = bpf_object__open_file("prog.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // 2. 오브젝트 로드
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // 3. 섹션명으로 프로그램 찾기
    prog = bpf_object__find_program_by_title(obj, "tracepoint/syscalls/sys_enter_execve");
    if (!prog) {
        fprintf(stderr, "Failed to find program in object\n");
        return 1;
    }

    // 4. tracepoint에 attach
    link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach to tracepoint\n");
        return 1;
    }

    printf("✅ Attached successfully. Check output with: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    // 5. 프로그램 유지
    while (1) sleep(1);
}
```

```bash
clang -O2 -g -Wall -o loader main.c -lbpf -lelf -lz
```

컴파일을 진행한다.

```bash
sudo ./loader
```

`loader`를 실행시켜 `prog.o`를 커널에 attach 시킨다.

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

다른 터미널에서 출력 내용을 확인한다.

```bash
            sudo-7085    [000] ....1  9969.236812: bpf_trace_printk: Hello, exec!

           <...>-7087    [005] ....1  9969.252758: bpf_trace_printk: Hello, exec!

           <...>-7088    [008] ....1 10007.001849: bpf_trace_printk: Hello, exec!

        lesspipe-7090    [007] ....1 10007.003726: bpf_trace_printk: Hello, exec!

        basename-7091    [007] ....1 10007.004604: bpf_trace_printk: Hello, exec!

           <...>-7093    [007] ....1 10007.006885: bpf_trace_printk: Hello, exec!

           <...>-7094    [008] ....1 10007.011392: bpf_trace_printk: Hello, exec!

           <...>-7095    [008] ....1 10009.939817: bpf_trace_printk: Hello, exec!

```

정상적으로 출력됨을 확인할 수 있다.
