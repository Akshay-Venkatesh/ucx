#
# Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2001-2018. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

if HAVE_CUDA

module_LTLIBRARIES      = libucm_cuda.la
libucm_cuda_la_CPPFLAGS = $(BASE_CPPFLAGS) $(CUDA_CPPFLAGS)
libucm_cuda_la_CFLAGS   = $(BASE_CFLAGS) $(CUDA_CFLAGS) $(LT_CFLAGS)
libucm_cuda_la_LIBADD   = ../libucm.la $(CUDA_LIBS) $(CUDART_LIBS)
libucm_cuda_la_LDFLAGS  = $(UCM_MODULE_LDFLAGS) \
                          $(patsubst %, -Xlinker %, $(CUDA_LDFLAGS)) \
                          -version-info $(SOVERSION)

noinst_HEADERS = \
	cudamem.h

libucm_cuda_la_SOURCES = \
	cudamem.c

include $(top_srcdir)/config/module.am

endif
