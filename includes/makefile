Example_DIR = c:\projects\cose\examples\spec-examples\new

.SUFFIXES:
.SUFFIXES: .bin .xml

.bin.xml:
	cbor2diag $< > $@.txt
	XmlPreparation.pl $@.txt > $@

all: Triple-01.xml \
	Mac-01.xml Mac-02.xml Mac-03.xml Mac-04.xml \
	Enc-01.xml Enc-02.xml \
	Sig-01.xml Sig-02.xml

Enc-01.bin: $(Example_DIR)\Enc-01.json.bin
	copy $** $@

Enc-02.bin: $(Example_DIR)\Enc-02.json.bin
	copy $** $@

Mac-01.bin: $(Example_DIR)\Mac-01.json.bin
	copy $** $@

Mac-02.bin: $(Example_DIR)\Mac-02.json.bin
	copy $** $@

Mac-03.bin: $(Example_DIR)\Mac-03.json.bin
	copy $** $@

Mac-04.bin: $(Example_DIR)\Mac-04.json.bin
	copy $** $@

Sig-01.bin: $(Example_DIR)\Sig-01.json.bin
	copy $** $@

Sig-02.bin: $(Example_DIR)\Sig-02.json.bin
	copy $** $@

Triple-01.bin: $(Example_DIR)\Triple-01.json.bin
	copy $** $@

