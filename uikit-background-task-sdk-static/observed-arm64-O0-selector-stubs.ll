; ModuleID = 'uikit-background-task-sdk-records/ios-arm64/client.m'
source_filename = "uikit-background-task-sdk-records/ios-arm64/client.m"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64-apple-ios18.0.0"

@.str = private unnamed_addr constant [6 x i8] c"v8@?0\00", align 1
@"__block_descriptor_32_e5_v8\01?0l" = linkonce_odr hidden unnamed_addr constant { i64, i64, ptr, ptr } { i64 0, i64 32, ptr @.str, ptr null }, align 8
@_NSConcreteGlobalBlock = external global ptr
@__block_literal_global = internal constant { ptr, i32, i32, ptr, ptr } { ptr @_NSConcreteGlobalBlock, i32 1342177280, i32 0, ptr @__nd_begin_block_invoke, ptr @"__block_descriptor_32_e5_v8\01?0l" }, align 8 #0
@__block_literal_global.1 = internal constant { ptr, i32, i32, ptr, ptr } { ptr @_NSConcreteGlobalBlock, i32 1342177280, i32 0, ptr @__nd_named_block_invoke, ptr @"__block_descriptor_32_e5_v8\01?0l" }, align 8 #0

; Function Attrs: noinline optnone ssp uwtable(sync)
define i64 @nd_begin(ptr noundef %0) #1 {
  %2 = alloca ptr, align 8
  store ptr null, ptr %2, align 8
  call void @llvm.objc.storeStrong(ptr %2, ptr %0) #2
  %3 = load ptr, ptr %2, align 8
  %4 = call i64 @"objc_msgSend$beginBackgroundTaskWithExpirationHandler:"(ptr noundef %3, ptr noundef undef, ptr noundef @__block_literal_global)
  call void @llvm.objc.storeStrong(ptr %2, ptr null) #2
  ret i64 %4
}

; Function Attrs: nounwind
declare void @llvm.objc.storeStrong(ptr, ptr) #2

; Function Attrs: noinline optnone ssp uwtable(sync)
define internal void @__nd_begin_block_invoke(ptr noundef %0) #3 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  store ptr %0, ptr %3, align 8
  call void @record_expiration()
  ret void
}

declare void @record_expiration() #4

declare ptr @"objc_msgSend$beginBackgroundTaskWithExpirationHandler:"(ptr, ptr, ...)

; Function Attrs: noinline optnone ssp uwtable(sync)
define i64 @nd_named(ptr noundef %0, ptr noundef %1) #1 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr null, ptr %3, align 8
  call void @llvm.objc.storeStrong(ptr %3, ptr %0) #2
  store ptr null, ptr %4, align 8
  call void @llvm.objc.storeStrong(ptr %4, ptr %1) #2
  %5 = load ptr, ptr %3, align 8
  %6 = load ptr, ptr %4, align 8
  %7 = call i64 @"objc_msgSend$beginBackgroundTaskWithName:expirationHandler:"(ptr noundef %5, ptr noundef undef, ptr noundef %6, ptr noundef @__block_literal_global.1)
  call void @llvm.objc.storeStrong(ptr %4, ptr null) #2
  call void @llvm.objc.storeStrong(ptr %3, ptr null) #2
  ret i64 %7
}

; Function Attrs: noinline optnone ssp uwtable(sync)
define internal void @__nd_named_block_invoke(ptr noundef %0) #3 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  store ptr %0, ptr %3, align 8
  call void @record_expiration()
  ret void
}

declare ptr @"objc_msgSend$beginBackgroundTaskWithName:expirationHandler:"(ptr, ptr, ...)

attributes #0 = { "objc_arc_inert" }
attributes #1 = { noinline optnone ssp uwtable(sync) "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "stack-protector-buffer-size"="8" "target-cpu"="apple-a10" "target-features"="+aes,+crc,+fp-armv8,+lor,+neon,+pan,+perfmon,+rdm,+sha2,+v8a,+vh" }
attributes #2 = { nounwind }
attributes #3 = { noinline optnone ssp uwtable(sync) "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="apple-a10" "target-features"="+aes,+crc,+fp-armv8,+lor,+neon,+pan,+perfmon,+rdm,+sha2,+v8a,+vh" }
attributes #4 = { "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "stack-protector-buffer-size"="8" "target-cpu"="apple-a10" "target-features"="+aes,+crc,+fp-armv8,+lor,+neon,+pan,+perfmon,+rdm,+sha2,+v8a,+vh" }

!llvm.module.flags = !{!0, !1, !2, !3, !4, !5, !6, !7, !8, !9, !10}
!llvm.ident = !{!11}

!0 = !{i32 2, !"SDK Version", [2 x i32] [i32 26, i32 5]}
!1 = !{i32 1, !"Objective-C Version", i32 2}
!2 = !{i32 1, !"Objective-C Image Info Version", i32 0}
!3 = !{i32 1, !"Objective-C Image Info Section", !"__DATA,__objc_imageinfo,regular,no_dead_strip"}
!4 = !{i32 1, !"Objective-C Garbage Collection", i8 0}
!5 = !{i32 1, !"Objective-C Class Properties", i32 64}
!6 = !{i32 1, !"Objective-C Enforce ClassRO Pointer Signing", i8 0}
!7 = !{i32 1, !"wchar_size", i32 4}
!8 = !{i32 8, !"PIC Level", i32 2}
!9 = !{i32 7, !"uwtable", i32 1}
!10 = !{i32 7, !"frame-pointer", i32 1}
!11 = !{!"Apple clang version 21.0.0 (clang-2100.1.1.101)"}
