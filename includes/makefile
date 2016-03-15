Example_DIR = c:\projects\cose\examples\new\spec-examples
DUMPER_DIR = c:\projects\cose\cose-c\build\dist\dumper\debug

.SUFFIXES:
.SUFFIXES: .bin .fred .xml

{$(Example_DIR)}.bin.xml:
	$(DUMPER_DIR)\cose_dumper.exe -xml=yes -wrap=68 $< > $@

all: Appendix_A.xml \
	Appendix_B_1_1.xml Appendix_B_1_2.xml Appendix_B_1_3.xml Appendix_B_1_4.xml \
	Appendix_B_2_1.xml \
	Appendix_B_3_1.xml Appendix_B_3_2.xml Appendix_B_3_3.xml Appendix_B_3_4.xml \
	Appendix_B_4_1.xml Appendix_B_4_2.xml \
	Appendix_B_5_1.xml Appendix_B_5_2.xml Appendix_B_5_3.xml Appendix_B_5_4.xml \
	Appendix_B_6_1.xml \
	private-keyset.xml public-keyset.xml



