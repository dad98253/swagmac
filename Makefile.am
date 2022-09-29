## Process this file with automake to produce Makefile.in

SWAGMACCLUDES =
SWAGMACMAIN = src/swagmac.c
SWAGMACSOURCES = 

ACLOCAL_AMFLAGS = -I m4 --install

EXTRA_DIST = m4/Makefile.in build-aux/Makefile.in
	

distclean-local:
	@rm config.status configure config.log
	@rm Makefile
	@rm -r autom4te.cache/
	@rm aclocal.m4
	@rm Makefile.in

#build swagmac
bin_PROGRAMS = $(top_builddir)/bin/swagmac 
#add in main()
__top_builddir__bin_swagmac_SOURCES = $(SWAGMACMAIN)

if FREEBSD
__top_builddir__bin_swagmac_LDFLAGS = -Wl,-Map,loadmap.txt -lxml2 -ltelnet -lmongoc-1.0 -lbson-1.0
else
__top_builddir__bin_swagmac_LDFLAGS = -Wl,-Map,loadmap.txt -lxml2 -ltelnet -lmongoc-1.0 -lbson-1.0
endif

#add header files
noinst_HEADERS = $(SWAGMACCLUDES)

help:
	-@echo "make                    --> build swagmac"
	-@echo "make clean              --> delete what was built"
	-@echo "make distclean          --> delete auto tools products"
	-@echo "make dist               --> build distribution package"

#__top_builddir__bin_swagmac_LDADD = lib/libpass.a $(lib_LTLIBRARIES)
#AM_CPPFLAGS = -DTEXTMODEONLY -DNOECBM2X -I"/home/dad/repositories/linux/swagmac/tutlib2" -I"/home/dad/repositories/linux/treStatic" -I"/home/dad/repositories/linux/swagmac/Resourcelib"
AM_CPPFLAGS = $(DEPS_CFLAGS) $(MY_CPPFLAGS)
AM_CXXFLAGS = -W -Wall -fmessage-length=0
#AM_LDFLAGS = -static
#AM_LIBS = $(DEPS_LIBS)

	
