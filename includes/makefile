Example_DIR = c:\projects\cose\examples\new\spec-examples
DUMPER_DIR = c:\projects\cose\cose-c\build\dist\dumper\debug

.SUFFIXES:
.SUFFIXES: .bin .xml

.bin.xml:
	$(DUMPER_DIR)\cose_dumper.exe -xml=yes -wrap=68 $< > $@

all: Triple-01.xml \
	Mac-01.xml Mac-02.xml Mac-03.xml Mac-04.xml \
	Mac0-01.xml \
	Enc-01.xml Enc-02.xml Enc-03.xml Enc-04.xml Enc-05.xml Enc-06.xml \
	Sig-01.xml Sig-02.xml Sig-03.xml Sig-04.xml \
	Sig0-01.xml \
	public-keyset.xml private-keyset.xml

private-keyset.xml: private-keyset.bin
	$(DUMPER_DIR)\cose_dumper.exe -xml=yes -type=keyset -wrap=68 $*.bin > $@

public-keyset.bin: $(Example_DIR)\public-keyset.bin
	copy $** $@

public-keyset.xml: public-keyset.bin
	$(DUMPER_DIR)\cose_dumper.exe -xml=yes -type=keyset -wrap=68 $*.bin > $@

Enc-01.bin: $(Example_DIR)\Enc-01.json.bin
	copy $** $@

Enc-02.bin: $(Example_DIR)\Enc-02.json.bin
	copy $** $@

Enc-03.bin: $(Example_DIR)\Enc-03.json.bin
	copy $** $@

Enc-04.bin: $(Example_DIR)\Enc-04.json.bin
	copy $** $@

Enc-05.bin: $(Example_DIR)\Enc-05.json.bin
	copy $** $@

Enc-06.bin: $(Example_DIR)\Enc-06.json.bin
	copy $** $@

Mac-01.bin: $(Example_DIR)\Mac-01.json.bin
	copy $** $@

Mac-02.bin: $(Example_DIR)\Mac-02.json.bin
	copy $** $@

Mac-03.bin: $(Example_DIR)\Mac-03.json.bin
	copy $** $@

Mac-04.bin: $(Example_DIR)\Mac-04.json.bin
	copy $** $@

Mac0-01.bin: $(Example_DIR)\Mac0-01.json.bin
	copy $** $@

Sig-01.bin: $(Example_DIR)\Sig-01.json.bin
	copy $** $@

Sig-02.bin: $(Example_DIR)\Sig-02.json.bin
	copy $** $@

Sig-03.bin: $(Example_DIR)\Sig-03.json.bin
	copy $** $@

Sig-04.bin: $(Example_DIR)\Sig-04.json.bin
	copy $** $@

Sig0-01.bin: $(Example_DIR)\Sig0-01.json.bin
	copy $** $@

Triple-01.bin: $(Example_DIR)\Triple-01.json.bin
	copy $** $@

private-keyset.bin: $(Example_DIR)\private-keyset.bin
	copy $** $@
