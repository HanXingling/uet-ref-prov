/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* adds build_id to version if it was defined */
#define BUILD_ID ""

/* EFA unit testing */
#define EFA_UNIT_TEST 0

/* dlopen CUDA libraries */
#define ENABLE_CUDA_DLOPEN 0

/* defined to 1 if libfabric was configured with --enable-debug, 0 otherwise
   */
#define ENABLE_DEBUG 0

/* EFA memory poisoning support for debugging */
/* #undef ENABLE_EFA_POISONING */

/* dlopen gdrcopy libraries */
#define ENABLE_GDRCOPY_DLOPEN 0

/* Define to 1 to enable memhooks memory monitor */
#define ENABLE_MEMHOOKS_MONITOR 1

/* dlopen ROCR libraries */
#define ENABLE_ROCR_DLOPEN 0

/* Define to 1 to enable uffd memory monitor */
#define ENABLE_UFFD_MONITOR 1

/* dlopen ZE libraries */
#define ENABLE_ZE_DLOPEN 0

/* define when building with FABRIC_DIRECT support */
/* #undef FABRIC_DIRECT_ENABLED */

/* Define to 1 if you have the <accel-config/libaccel_config.h> header file.
   */
/* #undef HAVE_ACCEL_CONFIG_LIBACCEL_CONFIG_H */

/* Define to 1 if the linker supports alias attribute. */
#define HAVE_ALIAS_ATTRIBUTE 1

/* Set to 1 to use c11 atomic functions */
#define HAVE_ATOMICS 1

/* Set to 1 to use c11 atomic `least` types */
#define HAVE_ATOMICS_LEAST_TYPES 1

/* bgq provider is built */
#define HAVE_BGQ 0

/* bgq provider is built as DSO */
#define HAVE_BGQ_DL 0

/* Set to 1 to use built-in intrincics atomics */
#define HAVE_BUILTIN_ATOMICS 1

/* Set to 1 to use built-in intrinsics memory model aware atomics */
#define HAVE_BUILTIN_MM_ATOMICS 1

/* Set to 1 to use built-in intrinsics memory model aware 128-bit integer
   atomics */
/* #undef HAVE_BUILTIN_MM_INT128_ATOMICS */

/* Indicates if EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE is defined */
#define HAVE_CAPS_RDMA_WRITE 0

/* Indicates if EFADV_DEVICE_ATTR_CAPS_RNR_RETRY is defined */
#define HAVE_CAPS_RNR_RETRY 1

/* Define to 1 if clock_gettime is available. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the <cmocka.h> header file. */
/* #undef HAVE_CMOCKA_H */

/* Set to 1 to use cpuid */
#define HAVE_CPUID 1

/* Define to 1 if criterion requested and available */
#define HAVE_CRITERION 0

/* CUDA support */
#define HAVE_CUDA 0

/* CUDA dmabuf support */
#define HAVE_CUDA_DMABUF 0

/* Define to 1 if you have the <cuda_runtime.h> header file. */
/* #undef HAVE_CUDA_RUNTIME_H */

/* Define to 1 if you have the declaration of `ethtool_cmd_speed', and to 0 if
   you don't. */
#define HAVE_DECL_ETHTOOL_CMD_SPEED 1

/* Define to 1 if you have the declaration of `IORING_CQE_F_MORE', and to 0 if
   you don't. */
/* #undef HAVE_DECL_IORING_CQE_F_MORE */

/* Define to 1 if you have the declaration of `io_uring_prep_poll_multishot',
   and to 0 if you don't. */
/* #undef HAVE_DECL_IO_URING_PREP_POLL_MULTISHOT */

/* Define to 1 if you have the declaration of `SPEED_UNKNOWN', and to 0 if you
   don't. */
#define HAVE_DECL_SPEED_UNKNOWN 1

/* Define to 1 if you have the declaration of
   `UCP_WORKER_FLAG_IGNORE_REQUEST_LEAK', and to 0 if you don't. */
/* #undef HAVE_DECL_UCP_WORKER_FLAG_IGNORE_REQUEST_LEAK */

/* Define to 1 if you have the declaration of `__syscall', and to 0 if you
   don't. */
#define HAVE_DECL___SYSCALL 0

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* dmabuf_peer_mem provider is built */
#define HAVE_DMABUF_PEER_MEM 1

/* dmabuf_peer_mem provider is built as DSO */
#define HAVE_DMABUF_PEER_MEM_DL 0

/* i915 DRM header */
#define HAVE_DRM 0

/* efa provider is built */
#define HAVE_EFA 1

/* Indicates EFA supports extensible CQ */
#define HAVE_EFADV_CQ_EX 0

/* Indicates if EFA supports 128 bytes in-order in writing. */
#define HAVE_EFA_DATA_IN_ORDER_ALIGNED_128_BYTES 0

/* efa provider is built as DSO */
#define HAVE_EFA_DL 0

/* Indicates if ibv_reg_dmabuf_mr verbs is available */
#define HAVE_EFA_DMABUF_MR 1

/* Define to 1 if you have the <elf.h> header file. */
#define HAVE_ELF_H 1

/* Define if you have epoll support. */
#define HAVE_EPOLL 1

/* Define to 1 if you have the `epoll_create' function. */
#define HAVE_EPOLL_CREATE 1

/* Set to 1 to use ethtool */
#define HAVE_ETHTOOL 1

/* defined to 1 if libfabric was configured with --enable-profile, 0 otherwise
   */
/* #undef HAVE_FABRIC_PROFILE */

/* Define to 1 if you have the <gdrapi.h> header file. */
/* #undef HAVE_GDRAPI_H */

/* gdrcopy support */
#define HAVE_GDRCOPY 0

/* Define to 1 if you have the `getifaddrs' function. */
#define HAVE_GETIFADDRS 1

/* gni provider is built */
#define HAVE_GNI 0

/* Define to 1 if the system has the type `gni_ct_cqw_post_descriptor_t'. */
/* #undef HAVE_GNI_CT_CQW_POST_DESCRIPTOR_T */

/* gni provider is built as DSO */
#define HAVE_GNI_DL 0

/* Define to 1 if you have the <habanalabs/synapse_api.h> header file. */
/* #undef HAVE_HABANALABS_SYNAPSE_API_H */

/* hook_debug provider is built */
#define HAVE_HOOK_DEBUG 1

/* hook_debug provider is built as DSO */
#define HAVE_HOOK_DEBUG_DL 0

/* hook_hmem provider is built */
#define HAVE_HOOK_HMEM 1

/* hook_hmem provider is built as DSO */
#define HAVE_HOOK_HMEM_DL 0

/* Define to 1 if you have the <hsa/hsa_ext_amd.h> header file. */
/* #undef HAVE_HSA_HSA_EXT_AMD_H */

/* Indicates if libibverbs has ibv_is_fork_initialized */
#define HAVE_IBV_IS_FORK_INITIALIZED 1

/* Define to 1 if you have the <infiniband/efadv.h> header file. */
#define HAVE_INFINIBAND_EFADV_H 1

/* Define to 1 if you have the <infiniband/verbs.h> header file. */
#define HAVE_INFINIBAND_VERBS_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if kdreg available */
/* #undef HAVE_KDREG */

/* Define to 1 if you have the <level_zero/ze_api.h> header file. */
/* #undef HAVE_LEVEL_ZERO_ZE_API_H */

/* Define to 1 if you have the `dl' library (-ldl). */
#define HAVE_LIBDL 1

/* i915 DRM header */
#define HAVE_LIBDRM 0

/* Whether we have libl or libnl3 */
#define HAVE_LIBNL3 1

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* io_uring support */
/* #undef HAVE_LIBURING */

/* Define to 1 if you have the <liburing.h> header file. */
/* #undef HAVE_LIBURING_H */

/* Define to 1 if you have the <linux/idxd.h> header file. */
#define HAVE_LINUX_IDXD_H 1

/* Define to 1 if you have the <linux/mman.h> header file. */
#define HAVE_LINUX_MMAN_H 1

/* Whether we have __builtin_ia32_rdpmc() and linux/perf_event.h file or not
   */
#define HAVE_LINUX_PERF_RDPMC 1

/* Define to 1 if you have the <linux/userfaultfd.h> header file. */
#define HAVE_LINUX_USERFAULTFD_H 1

/* Build with LTTng userspace tracepoints */
#define HAVE_LTTNG 0

/* Define to 1 if you have the <lttng/tracepoint.h> header file. */
/* #undef HAVE_LTTNG_TRACEPOINT_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* mrail provider is built */
#define HAVE_MRAIL 1

/* mrail provider is built as DSO */
#define HAVE_MRAIL_DL 0

/* Define to 1 if you have the <netlink/netlink.h> header file. */
/* #undef HAVE_NETLINK_NETLINK_H */

/* Define to 1 if you have the <netlink/version.h> header file. */
#define HAVE_NETLINK_VERSION_H 1

/* Build with Neuron support */
#define HAVE_NEURON 0

/* Define to 1 if you have the <nrt/nrt.h> header file. */
/* #undef HAVE_NRT_NRT_H */

/* Define to 1 if you have the <numa.h> header file. */
#define HAVE_NUMA_H 1

/* opx provider is built */
#define HAVE_OPX 0

/* opx provider is built as DSO */
#define HAVE_OPX_DL 0

/* perf provider is built */
#define HAVE_PERF 1

/* perf provider is built as DSO */
#define HAVE_PERF_DL 0

/* profile provider is built */
#define HAVE_PROFILE 0

/* profile provider is built as DSO */
#define HAVE_PROFILE_DL 0

/* psm2 provider is built */
#define HAVE_PSM2 0

/* psm2_am_register_handlers_2 function is present */
#define HAVE_PSM2_AM_REGISTER_HANDLERS_2 0

/* psm2 provider is built as DSO */
#define HAVE_PSM2_DL 0

/* Define to 1 if you have the <psm2.h> header file. */
/* #undef HAVE_PSM2_H */

/* psm2_info_query function is present */
#define HAVE_PSM2_INFO_QUERY 0

/* psm2_mq_fp_msg function is present and enabled */
#define HAVE_PSM2_MQ_FP_MSG 0

/* psm2_mq_ipeek_dequeue_multi function is present and enabled */
#define HAVE_PSM2_MQ_REQ_USER 0

/* PSM2 source is built-in */
#define HAVE_PSM2_SRC 0

/* psm3 provider is built */
#define HAVE_PSM3 0

/* psm3 provider is built as DSO */
#define HAVE_PSM3_DL 0

/* PSM3 source is built-in */
#define HAVE_PSM3_SRC 1

/* Define to 1 if you have the <rdma/hfi/hfi1_user.h> header file. */
#define HAVE_RDMA_HFI_HFI1_USER_H 1

/* Define to 1 if you have the <rdma/rdma_cma.h> header file. */
/* #undef HAVE_RDMA_RDMA_CMA_H */

/* Define to 1 if you have the <rdma/rv_user_ioctls.h> header file. */
/* #undef HAVE_RDMA_RV_USER_IOCTLS_H */

/* Indicates if efadv_device_attr has max_rdma_size */
#define HAVE_RDMA_SIZE 1

/* Define to 1 to only look for dl providers under default location if
   FI_PROVIDER_PATH is not set */
#define HAVE_RESTRICTED_DL 0

/* ROCR support */
#define HAVE_ROCR 0

/* rstream provider is built */
#define HAVE_RSTREAM 1

/* rstream provider is built as DSO */
#define HAVE_RSTREAM_DL 0

/* rxd provider is built */
#define HAVE_RXD 1

/* rxd provider is built as DSO */
#define HAVE_RXD_DL 0

/* rxm provider is built */
#define HAVE_RXM 1

/* rxm provider is built as DSO */
#define HAVE_RXM_DL 0

/* shm provider is built */
#define HAVE_SHM 1

/* shm provider is built as DSO */
#define HAVE_SHM_DL 0

/* sm2 provider is built */
#define HAVE_SM2 1

/* sm2 provider is built as DSO */
#define HAVE_SM2_DL 0

/* sockets provider is built */
#define HAVE_SOCKETS 1

/* sockets provider is built as DSO */
#define HAVE_SOCKETS_DL 0

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if compiler/linker support symbol versioning. */
#define HAVE_SYMVER_SUPPORT 1

/* SynapseAI support */
#define HAVE_SYNAPSEAI 0

/* Define to 1 if you have the <sys/auxv.h> header file. */
#define HAVE_SYS_AUXV_H 1

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syscall.h> header file. */
#define HAVE_SYS_SYSCALL_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* tcp provider is built */
#define HAVE_TCP 1

/* tcp provider is built as DSO */
#define HAVE_TCP_DL 0

/* trace provider is built */
#define HAVE_TRACE 1

/* trace provider is built as DSO */
#define HAVE_TRACE_DL 0

/* Define to 1 if typeof works with your compiler. */
#define HAVE_TYPEOF 1

/* Define to 1 if you have the <ucp/api/ucp.h> header file. */
/* #undef HAVE_UCP_API_UCP_H */

/* ucx provider is built */
#define HAVE_UCX 0

/* ucx provider is built as DSO */
#define HAVE_UCX_DL 0

/* udp provider is built */
#define HAVE_UDP 1

/* udp provider is built as DSO */
#define HAVE_UDP_DL 0

/* Define to 1 if platform supports userfault fd unmap */
#define HAVE_UFFD_UNMAP 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* usnic provider is built */
#define HAVE_USNIC 1

/* usnic provider is built as DSO */
#define HAVE_USNIC_DL 0

/* Define to 1 if you have the <uuid/uuid.h> header file. */
/* #undef HAVE_UUID_UUID_H */

/* verbs provider is built */
#define HAVE_VERBS 0

/* verbs provider is built as DSO */
#define HAVE_VERBS_DL 0

/* XPMEM support availability */
#define HAVE_XPMEM 0

/* Define to 1 if you have the <xpmem.h> header file. */
/* #undef HAVE_XPMEM_H */

/* ZE support */
#define HAVE_ZE 0

/* Define to 1 if you have the `__clear_cache' function. */
#define HAVE___CLEAR_CACHE 1

/* Define to 1 if you have the `__curbrk' function. */
#define HAVE___CURBRK 1

/* Set to 1 to use 128-bit ints */
#define HAVE___INT128 1

/* Define to 1 if you have the `__syscall' function. */
/* #undef HAVE___SYSCALL */

/* Define to 1 to enable valgrind annotations */
/* #undef INCLUDE_VALGRIND */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* fabric direct address vector */
#define OPX_AV FI_AV_UNSPEC

/* fabric direct memory region */
#define OPX_MR FI_MR_SCALABLE

/* fabric direct progress */
#define OPX_PROGRESS FI_PROGRESS_UNSPEC

/* fabric direct reliability */
#define OPX_RELIABILITY OFI_RELIABILITY_KIND_ONLOAD

/* fabric direct thread */
#define OPX_THREAD FI_THREAD_ENDPOINT

/* Name of package */
#define PACKAGE "libfabric"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "ofiwg@lists.openfabrics.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libfabric"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libfabric 1.20.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libfabric"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.20.1"

/* Whether we have CUDA runtime or not */
#define PSM3_CUDA 0

/* PSM3 built with instruction set */
#define PSM3_MARCH "avx2"

/* Whether we have oneAPI Level-Zero runtime or not */
#define PSM3_ONEAPI 0

/* Define to 1 if pthread_spin_init is available. */
#define PT_LOCK_SPIN 1

/* Whether DSA support is available */
#define SHM_HAVE_DSA 0

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Whether to build the fake usNIC verbs provider or not */
#define USNIC_BUILD_FAKE_VERBS_DRIVER 0

/* Whether infiniband/verbs.h has ibv_reg_dmabuf_mr() support or not */
#define VERBS_HAVE_DMABUF_MR 1

/* Whether infiniband/verbs.h has ibv_query_device_ex() support or not */
#define VERBS_HAVE_QUERY_EX 1

/* Whether rdma/rdma_cma.h has rdma_establish() support or not */
#define VERBS_HAVE_RDMA_ESTABLISH 0

/* Whether infiniband/verbs.h has XRC support or not */
#define VERBS_HAVE_XRC 0

/* Version number of package */
#define VERSION "1.20.1"

/* Define to __typeof__ if your compiler spells it that way. */
/* #undef typeof */


#if defined(__linux__) && (defined(__x86_64__) || defined(__amd64__) || defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)) && ENABLE_MEMHOOKS_MONITOR
#define HAVE_MEMHOOKS_MONITOR 1
#else
#define HAVE_MEMHOOKS_MONITOR 0
#endif

#if HAVE_UFFD_UNMAP && ENABLE_UFFD_MONITOR
#define HAVE_UFFD_MONITOR 1
#else
#define HAVE_UFFD_MONITOR 0
#endif

